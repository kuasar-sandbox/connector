/* SPDX-License-Identifier: Apache-2.0 */
/* Area policy and per-attachment/Pool accounting. All configuration changes
 * hold the worker barrier; packet workers only reserve/release atomic counters.
 * NAT owns mappings, timeouts, TCP state, checksums and address/port allocation. */
#include <nat/nat44-ed/nat44_ed_policy.h>
#include <vlib/unix/plugin.h>
#include <vlib/vlib.h>
#include <vnet/adj/adj.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#define EG_POOLS 64
#define EG_AREAS 256
#define EG_RULES 4096
typedef struct
{
  ip4_address_t network, target;
  u32 prefix, pool;
  u16 first, last, target_port;
  u8 proto, allow;
} rule_t;
typedef struct
{
  u8 present;
  u32 fib;
  u64 limit;
  ip4_address_t *addresses;
} exit_pool_t;
typedef struct
{
  u32 id;
  rule_t *acl, *dnat, *routes;
  exit_pool_t pools[EG_POOLS];
} area_t;
typedef struct
{
  u8 active, revoked;
  u32 area, table;
  u64 current[EG_POOLS], created[EG_POOLS], released[EG_POOLS];
  u64 rollback[EG_POOLS], denied[EG_POOLS], policy_denied;
} attachment_t;
static area_t *areas, staged;
static u8 staging;
static uword *area_by_id;
static attachment_t *attachments;
static u32 (*native_walk) (nat44_ed_policy_visit_t, void *);
static u32 (*native_expire) (u32);
static u32 (*return_mtu) (u32);

static void
free_area (area_t *a)
{
  vec_free (a->acl);
  vec_free (a->dnat);
  vec_free (a->routes);
  for (u32 i = 0; i < EG_POOLS; i++)
    vec_free (a->pools[i].addresses);
  clib_memset (a, 0, sizeof (*a));
}
static int
prefix_matches (const rule_t *r, ip4_address_t dst)
{
  u32 mask = r->prefix ? ~0U << (32 - r->prefix) : 0;
  return (clib_net_to_host_u32 (dst.as_u32) & mask) == clib_net_to_host_u32 (r->network.as_u32);
}
static int
matches (const rule_t *r, ip4_address_t dst, u16 port, u8 proto)
{
  return prefix_matches (r, dst) && (!r->proto || r->proto == proto)
         && (!r->first || (port >= r->first && port <= r->last));
}
static int
resolve_path (u32 fib, ip4_address_t dst, u64 *signature, u8 *neighbor)
{
  u32 lbi = ip4_fib_forwarding_lookup (fib, &dst);
  for (u32 depth = 0; depth < 8; depth++)
    {
      const load_balance_t *lb = load_balance_get (lbi);
      if (lb->lb_n_buckets != 1)
        return -1;
      const dpo_id_t *dpo = load_balance_get_bucket_i (lb, 0);
      if (dpo->dpoi_type == DPO_LOAD_BALANCE)
        {
          lbi = dpo->dpoi_index;
          continue;
        }
      if (dpo->dpoi_type != DPO_ADJACENCY && dpo->dpoi_type != DPO_ADJACENCY_INCOMPLETE
          && dpo->dpoi_type != DPO_ADJACENCY_GLEAN)
        return -1;
      ip_adjacency_t *adj = adj_get (dpo->dpoi_index);
      u32 sw = adj->rewrite_header.sw_if_index;
      if (sw == ~0 || !vnet_sw_interface_is_admin_up (vnet_get_main (), sw))
        return -1;
      if (neighbor)
        *neighbor = dpo->dpoi_type == DPO_ADJACENCY;
      u32 hop = dpo->dpoi_type == DPO_ADJACENCY_GLEAN ? dst.as_u32
                                                      : adj->sub_type.nbr.next_hop.ip4.as_u32;
      *signature = ((u64)sw << 32) | hop;
      return adj->rewrite_header.max_l3_packet_bytes;
    }
  return -1;
}
static int
select_policy (u32 fib, u8 proto, ip4_address_t dst, u16 port, nat44_ed_policy_decision_t *d)
{
  if (fib >= vec_len (attachments) || !attachments[fib].active || attachments[fib].revoked)
    return -1;
  attachment_t *c = &attachments[fib];
  area_t *a = &areas[c->area];
  rule_t *r;
  u8 allowed = 0;
  u32 pool = ~0, best = 0;
  vec_foreach (r, a->acl) if (matches (r, dst, clib_net_to_host_u16 (port), proto))
  {
    allowed = r->allow;
    break;
  }
  if (!allowed)
    return -1;
  d->backend_addr = dst;
  d->backend_port = port;
  vec_foreach (r, a->dnat) if (matches (r, dst, clib_net_to_host_u16 (port), proto))
  {
    pool = r->pool;
    d->backend_addr = r->target;
    if (r->target_port)
      d->backend_port = clib_host_to_net_u16 (r->target_port);
    break;
  }
  if (pool == ~0)
    vec_foreach (r, a->routes)
    {
      if (prefix_matches (r, dst) && (pool == ~0 || r->prefix > best))
        {
          pool = r->pool;
          best = r->prefix;
        }
    }
  if (pool >= EG_POOLS || !a->pools[pool].present)
    return -1;
  exit_pool_t *p = &a->pools[pool];
  d->cookie = ((u64)fib << 32) | pool;
  d->addresses = p->addresses;
  d->address_count = vec_len (p->addresses);
  d->tx_fib_index = d->return_key_fib = p->fib;
  return resolve_path (p->fib, d->backend_addr, &d->path_signature, 0) < 0 ? -1 : 1;
}
static int
managed (u32 fib)
{
  return fib < vec_len (attachments) && attachments[fib].active;
}
static int
prepare (u32 fib, u32 thread, u8 proto, ip4_address_t local, u16 lport, ip4_address_t remote,
         u16 rport, nat44_ed_policy_decision_t *d)
{
  if (!managed (fib))
    return 0;
  int result = select_policy (fib, proto, remote, rport, d);
  if (result < 0)
    __atomic_fetch_add (&attachments[fib].policy_denied, 1, __ATOMIC_RELAXED);
  return result;
}
static int
reserve (u64 cookie, u32 thread)
{
  attachment_t *c = &attachments[cookie >> 32];
  u32 id = (u32)cookie;
  u64 limit = areas[c->area].pools[id].limit;
  u64 n = __atomic_load_n (&c->current[id], __ATOMIC_RELAXED);
  for (;;)
    {
      if (limit && n >= limit)
        {
          __atomic_fetch_add (&c->denied[id], 1, __ATOMIC_RELAXED);
          return 0;
        }
      if (__atomic_compare_exchange_n (&c->current[id], &n, n + 1, 0, __ATOMIC_RELAXED,
                                       __ATOMIC_RELAXED))
        return 1;
    }
}
static void
commit (u64 cookie)
{
  __atomic_fetch_add (&attachments[cookie >> 32].created[(u32)cookie], 1, __ATOMIC_RELAXED);
}
static void
release (u64 cookie, u8 committed)
{
  attachment_t *c = &attachments[cookie >> 32];
  u32 id = (u32)cookie;
  u64 old = __atomic_fetch_sub (&c->current[id], 1, __ATOMIC_RELAXED);
  ALWAYS_ASSERT (old > 0);
  __atomic_fetch_add (committed ? &c->released[id] : &c->rollback[id], 1, __ATOMIC_RELAXED);
}
static int
path_mtu (u64 cookie, u64 expected, u32 inside, u32 route, ip4_address_t dst, ip4_address_t forward,
          u8 out2in)
{
  if (cookie != NAT44_ED_POLICY_NONE)
    {
      u32 fib = cookie >> 32, id = (u32)cookie;
      if (!managed (fib) || attachments[fib].revoked || id >= EG_POOLS)
        return -1;
      exit_pool_t *p = &areas[attachments[fib].area].pools[id];
      u64 actual;
      int mtu = p->present ? resolve_path (p->fib, forward, &actual, 0) : -1;
      if (mtu < 0 || actual != expected)
        return -1;
      if (!out2in)
        return mtu;
    }
  if (out2in && return_mtu)
    return return_mtu (inside);
  return 0;
}
/* Exported operations run with the worker barrier held by the caller. */
__clib_export int
egress_policy_context_bind (u32 fib, u32 table, u32 area)
{
  uword *index = hash_get (area_by_id, area);
  if (!index || managed (fib))
    return -1;
  vec_validate (attachments, fib);
  attachment_t *c = &attachments[fib];
  clib_memset (c, 0, sizeof (*c));
  c->table = table;
  c->area = index[0];
  c->active = 1;
  return 0;
}
__clib_export int
egress_policy_context_retire (u32 fib)
{
  if (!managed (fib))
    return 0;
  attachment_t *c = &attachments[fib];
  for (u32 i = 0; i < EG_POOLS; i++)
    if (c->current[i])
      return -1;
  clib_memset (c, 0, sizeof (*c));
  return 0;
}
__clib_export void
egress_policy_context_revoke (u32 fib)
{
  if (managed (fib))
    attachments[fib].revoked = 1;
}
typedef struct
{
  u32 fib, area;
  u8 flush, revoked;
} walk_t;
static int
visit (const nat44_ed_policy_flow_t *f, void *opaque)
{
  walk_t *w = opaque;
  if (w->revoked)
    return managed (f->inside_fib) && attachments[f->inside_fib].revoked;
  if (w->fib != ~0 && f->inside_fib != w->fib)
    return 0;
  if (w->area != ~0 && (!managed (f->inside_fib) || attachments[f->inside_fib].area != w->area))
    return 0;
  if (w->flush)
    return 1;
  nat44_ed_policy_decision_t d = { 0 };
  if (select_policy (f->inside_fib, f->proto, f->original_remote, f->original_remote_port, &d) < 0)
    return 1;
  if (d.cookie != f->cookie || d.backend_addr.as_u32 != f->backend.as_u32
      || d.backend_port != f->backend_port || d.tx_fib_index != f->route_fib
      || d.return_key_fib != f->outside_fib || d.path_signature != f->path_signature)
    return 1;
  for (u32 i = 0; i < d.address_count; i++)
    if (d.addresses[i].as_u32 == f->snat.as_u32)
      return 0;
  return 1;
}
__clib_export u32
egress_policy_context_flush (u32 fib)
{
  walk_t w = { .fib = fib, .area = ~0, .flush = 1 };
  return native_walk (visit, &w);
}
__clib_export u32
egress_policy_flush_revoked (void)
{
  walk_t w = { .revoked = 1 };
  return native_walk (visit, &w);
}
static clib_error_t *
config_cmd (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  const char *op = cmd->path + 14;
  if (!strcmp (op, "abort"))
    {
      free_area (&staged);
      staging = 0;
      return 0;
    }
  if (!strcmp (op, "begin"))
    {
      u32 id;
      if (!unformat (in, "area %u", &id) || id > 0xffffff
          || unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
        return clib_error_return (0, "invalid Area ID");
      if (!hash_get (area_by_id, id) && vec_len (areas) >= EG_AREAS)
        return clib_error_return (0, "Area capacity");
      free_area (&staged);
      staged.id = id;
      staging = 1;
      return 0;
    }
  if (!staging)
    return clib_error_return (0, "begin an Area transaction first");
  if (!strcmp (op, "commit"))
    {
      if (unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
        return clib_error_return (0, "unexpected argument");
      rule_t *r;
      vec_foreach (r, staged.routes) if (!staged.pools[r->pool].present) return clib_error_return (
          0, "unknown route Pool");
      vec_foreach (r, staged.dnat) if (!staged.pools[r->pool].present) return clib_error_return (
          0, "unknown DNAT Pool");
      for (u32 i = 0; i < EG_POOLS; i++)
        if (staged.pools[i].present && !vec_len (staged.pools[i].addresses))
          return clib_error_return (0, "Pool requires SNAT addresses");
      vlib_worker_thread_barrier_sync (vm);
      uword *found = hash_get (area_by_id, staged.id);
      u32 index = found ? found[0] : vec_len (areas);
      if (!found)
        {
          area_t empty = { 0 };
          vec_add1 (areas, empty);
          hash_set (area_by_id, staged.id, index);
        }
      area_t previous = areas[index];
      areas[index] = staged;
      clib_memset (&staged, 0, sizeof (staged));
      staging = 0;
      walk_t w = { .fib = ~0, .area = index };
      u32 removed = native_walk (visit, &w);
      free_area (&previous);
      vlib_worker_thread_barrier_release (vm);
      vlib_cli_output (vm, "{\"area\":%u,\"terminated\":%u}", areas[index].id, removed);
      return 0;
    }
  if (!strcmp (op, "pool"))
    {
      u32 id = ~0, table = ~0, limit = 0;
      if (!unformat (in, "id %u table %u limit %u", &id, &table, &limit) || id >= EG_POOLS
          || unformat_check_input (in) != UNFORMAT_END_OF_INPUT || staged.pools[id].present)
        return clib_error_return (0, "invalid or duplicate Pool");
      u32 fib = fib_table_find (FIB_PROTOCOL_IP4, table);
      if (fib == ~0)
        return clib_error_return (0, "unknown exit table");
      staged.pools[id] = (exit_pool_t){ .present = 1, .fib = fib, .limit = limit };
      return 0;
    }
  if (!strcmp (op, "address"))
    {
      u32 id = ~0;
      ip4_address_t addr;
      if (!unformat (in, "pool %u %U", &id, unformat_ip4_address, &addr) || id >= EG_POOLS
          || !staged.pools[id].present || !addr.as_u32
          || vec_len (staged.pools[id].addresses) >= 256
          || unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
        return clib_error_return (0, "invalid Pool address");
      vec_add1 (staged.pools[id].addresses, addr);
      return 0;
    }
  rule_t r = { 0 };
  u32 proto = 0, first = 0, last = 0, target_port = 0;
  if (!unformat (in, "dst %U/%u", unformat_ip4_address, &r.network, &r.prefix) || r.prefix > 32)
    return clib_error_return (0, "invalid destination prefix");
  if (!strcmp (op, "route"))
    {
      if (!unformat (in, "pool %u", &r.pool) || r.pool >= EG_POOLS)
        return clib_error_return (0, "invalid Pool");
    }
  else
    {
      if (!unformat (in, "proto %u ports %u %u", &proto, &first, &last)
          || (proto != 0 && proto != 1 && proto != 6 && proto != 17) || first > 65535
          || last > 65535 || first > last || (first && proto != 6 && proto != 17))
        return clib_error_return (0, "invalid protocol/ports");
      r.proto = proto;
      r.first = first;
      r.last = last;
      if (!strcmp (op, "acl"))
        {
          if (unformat (in, "allow"))
            r.allow = 1;
          else if (!unformat (in, "deny"))
            return clib_error_return (0, "expected allow/deny");
        }
      else if (!strcmp (op, "dnat"))
        {
          if ((proto != 6 && proto != 17)
              || !unformat (in, "pool %u target %U port %u", &r.pool, unformat_ip4_address,
                            &r.target, &target_port)
              || r.pool >= EG_POOLS || target_port > 65535 || !r.target.as_u32)
            return clib_error_return (0, "invalid DNAT");
          r.target_port = target_port;
        }
      else
        return clib_error_return (0, "unknown transaction operation");
    }
  u32 mask = r.prefix ? ~0U << (32 - r.prefix) : 0;
  if ((clib_net_to_host_u32 (r.network.as_u32) & ~mask)
      || unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "non-canonical prefix or extra argument");
  rule_t **rules = !strcmp (op, "acl")    ? &staged.acl
                   : !strcmp (op, "dnat") ? &staged.dnat
                                          : &staged.routes;
  if (vec_len (*rules) >= EG_RULES)
    return clib_error_return (0, "rule capacity");
  if (rules == &staged.routes)
    {
      rule_t *old;
      vec_foreach (
          old, *rules) if (old->prefix == r.prefix
                           && old->network.as_u32
                                  == r.network.as_u32) return clib_error_return (0,
                                                                                 "duplicate route");
    }
  vec_add1 (*rules, r);
  return 0;
}
#define EG_CMD(symbol, op)                                                                         \
  VLIB_CLI_COMMAND (symbol, static) = { .path = "egress-policy " op,                               \
                                        .short_help = "egress-policy " op,                         \
                                        .function = config_cmd,                                    \
                                        .is_mp_safe = 1 }
EG_CMD (eg_begin, "begin");
EG_CMD (eg_abort, "abort");
EG_CMD (eg_commit, "commit");
EG_CMD (eg_pool, "pool");
EG_CMD (eg_addr, "address");
EG_CMD (eg_acl, "acl");
EG_CMD (eg_dnat, "dnat");
EG_CMD (eg_route, "route");
static clib_error_t *
stats_cmd (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  vlib_worker_thread_barrier_sync (vm);
  for (u32 f = 0; f < vec_len (attachments); f++)
    {
      attachment_t *c = &attachments[f];
      if (!c->active)
        continue;
      for (u32 p = 0; p < EG_POOLS; p++)
        if (areas[c->area].pools[p].present || c->created[p])
          vlib_cli_output (
              vm,
              "{\"table\":%u,\"area\":%u,\"pool\":%u,\"current\":%llu,\"created\":%llu,"
              "\"released\":%llu,\"rollback\":%llu,\"denied\":%llu,\"policy_denied\":%llu}",
              c->table, areas[c->area].id, p, c->current[p], c->created[p], c->released[p],
              c->rollback[p], c->denied[p], c->policy_denied);
    }
  vlib_worker_thread_barrier_release (vm);
  return 0;
}
VLIB_CLI_COMMAND (eg_stats, static) = { .path = "egress-policy stats",
                                        .short_help = "egress-policy stats",
                                        .function = stats_cmd,
                                        .is_mp_safe = 1 };
static clib_error_t *
paths_cmd (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  vlib_worker_thread_barrier_sync (vm);
  area_t *area;
  ip4_address_t destination = { 0 };
  vec_foreach (area, areas) for (u32 p = 0; p < EG_POOLS; p++) if (area->pools[p].present)
  {
    u64 path = 0;
    u8 neighbor = 0;
    int mtu = resolve_path (area->pools[p].fib, destination, &path, &neighbor);
    ip4_address_t hop = { .as_u32 = (u32)path };
    vlib_cli_output (vm,
                     "{\"area\":%u,\"pool\":%u,\"route_available\":%s,\"neighbor_resolved\":%s,"
                     "\"interface_index\":%u,\"next_hop\":\"%U\",\"mtu\":%d}",
                     area->id, p, mtu > 0 ? "true" : "false", neighbor ? "true" : "false",
                     (u32)(path >> 32), format_ip4_address, &hop, mtu);
  }
  vlib_worker_thread_barrier_release (vm);
  return 0;
}
VLIB_CLI_COMMAND (eg_paths, static) = { .path = "egress-policy paths",
                                        .short_help = "egress-policy paths",
                                        .function = paths_cmd,
                                        .is_mp_safe = 1 };
static uword
reaper (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  uword *events = 0;
  for (;;)
    {
      vlib_process_wait_for_event_or_clock (vm, 0.1);
      vlib_process_get_events (vm, &events);
      vec_reset_length (events);
      vlib_worker_thread_barrier_sync (vm);
      native_expire (4096);
      vlib_worker_thread_barrier_release (vm);
    }
  return 0;
}
VLIB_REGISTER_NODE (eg_reaper)
    = { .function = reaper, .type = VLIB_NODE_TYPE_PROCESS, .name = "egress-native-reaper" };
static clib_error_t *
init (vlib_main_t *vm)
{
  int (*reg) (const nat44_ed_policy_hooks_t *)
      = vlib_get_plugin_symbol ("nat_plugin.so", "nat44_ed_policy_register");
  native_walk = vlib_get_plugin_symbol ("nat_plugin.so", "nat44_ed_policy_walk");
  native_expire = vlib_get_plugin_symbol ("nat_plugin.so", "nat44_ed_policy_expire");
  return_mtu = vlib_get_plugin_symbol ("egress_geneve_plugin.so", "egress_geneve_return_mtu");
  if (!reg || !native_walk || !native_expire || !return_mtu)
    return clib_error_return (0, "pinned Egress/NAT hooks unavailable");
  nat44_ed_policy_hooks_t h = { .managed = managed,
                                .prepare = prepare,
                                .reserve = reserve,
                                .commit = commit,
                                .release = release,
                                .path_mtu = path_mtu };
  if (reg (&h))
    return clib_error_return (0, "NAT hooks already registered");
  return 0;
}
VLIB_INIT_FUNCTION (init);
VLIB_PLUGIN_REGISTER ()
    = { .version = VPP_BUILD_VER, .description = "Connector Egress Area policy" };
