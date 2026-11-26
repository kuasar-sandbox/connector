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

#include <vppinfra/hash.h>
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
  u32 id, fib, return_fib;
  u64 limit;
  ip4_address_t *addresses;
} exit_pool_t;
typedef struct
{
  u32 id;
  u8 present;
  rule_t *acl, *dnat, *routes;
  exit_pool_t *pools;
  uword *pool_by_id;
} area_t;
typedef struct
{
  u32 id;
  u64 current, created, released, rollback, denied;
} eg_pool_counter_t;
/* An access identity has no inner address, MAC, encapsulation or device
 * index. Return-format/fencing versions may have separate forwarding FIBs,
 * but they all charge the same access/Pool quota. */
typedef struct
{
  u32 peer, local, slot, area;
} access_key_t;
typedef struct
{
  access_key_t key;
  u32 area, references;
  u64 policy_denied;
  eg_pool_counter_t *counters;
  uword *counter_by_id;
} access_t;
typedef struct
{
  u8 active, revoked;
  u32 access, table;
  u64 current;
} attachment_t;
static access_t *accesses;
static uword *access_by_key;
static access_t *
access_for (attachment_t *c)
{
  return &accesses[c->access];
}
static area_t *areas, staged, *pending;
static u8 staging, batching;
static uword *area_by_id;
static attachment_t *attachments;
static u32 (*native_walk) (nat44_ed_policy_visit_t, void *);
static u32 (*native_expire) (u32);
static u32 (*return_mtu) (u32);

static int (*native_address) (ip4_address_t, u8);
static int (*native_outside) (u32, u8);
typedef struct
{
  u32 sw, hop;
} path_key_t;
typedef struct
{
  path_key_t key;
  u32 table, fib;
  u8 configured, live;
} resource_t;
static resource_t *resources;
static uword *resource_by_path, *resource_by_fib, *public_addresses, *outside_interfaces;
static u32 next_resource_table = 1, *free_resource_tables;
static u8 collect_resources;

/* Resource versions are immutable. Changing a Pool path gives new mappings
 * another FIB; the old FIB and public addresses stay until their last mapping
 * is gone. No existing route is rewritten in place. */
static u32
resource_get (u32 sw, ip4_address_t hop)
{
  path_key_t key = { sw, hop.as_u32 };
  uword *found = hash_get_mem (resource_by_path, &key);
  if (found)
    return resources[found[0]].fib;
  u32 table;
  do
    {
      table
          = vec_len (free_resource_tables) ? vec_pop (free_resource_tables) : next_resource_table++;
      if (next_resource_table == ~0U)
        next_resource_table = 1;
    }
  while (!table || table == ~0U || fib_table_find (FIB_PROTOCOL_IP4, table) != ~0U);
  ip_table_create (FIB_PROTOCOL_IP4, table, 0, 1, 0);
  u32 fib = fib_table_find (FIB_PROTOCOL_IP4, table);
  if (fib == ~0U)
    return ~0U;
  fib_prefix_t prefix = { .fp_proto = FIB_PROTOCOL_IP4, .fp_len = 0 };
  ip46_address_t next = { .ip4 = hop };
  fib_table_entry_update_one_path (fib, &prefix, FIB_SOURCE_CLI, FIB_ENTRY_FLAG_NONE, DPO_PROTO_IP4,
                                   &next, sw, 0, 1, 0, FIB_ROUTE_PATH_FLAG_NONE);
  resource_t *r;
  pool_get_zero (resources, r);
  r->key = key;
  r->table = table;
  r->fib = fib;
  hash_set_mem_alloc (&resource_by_path, &key, r - resources);
  hash_set (resource_by_fib, fib, r - resources);
  collect_resources = 1;
  return fib;
}

typedef struct
{
  uword *addresses;
} resource_mark_t;
static void
mark_area_resources (area_t *a, resource_mark_t *mark)
{
  exit_pool_t *p;
  vec_foreach (p, a->pools)
  {
    uword *index = hash_get (resource_by_fib, p->fib);
    ALWAYS_ASSERT (index);
    resources[index[0]].configured = 1;
    ip4_address_t *addr;
    vec_foreach (addr, p->addresses) hash_set (mark->addresses, addr->as_u32, 1);
  }
}
static int
mark_flow_resource (const nat44_ed_policy_flow_t *flow, void *opaque)
{
  resource_mark_t *mark = opaque;
  uword *index = hash_get (resource_by_fib, flow->route_fib);
  ALWAYS_ASSERT (index);
  resources[index[0]].live = 1;
  if (!hash_get (mark->addresses, flow->snat.as_u32))
    hash_set (mark->addresses, flow->snat.as_u32, 2);
  return 0;
}
/* Candidate ingress addresses cannot intercept a retained SNAT mapping.
 * This visitor only observes: a nonzero return would delete a native flow. */
typedef struct
{
  u32 address;
  u8 conflict;
} vtep_check_t;
static int
check_vtep_flow (const nat44_ed_policy_flow_t *flow, void *opaque)
{
  vtep_check_t *check = opaque;
  if (flow->snat.as_u32 == check->address)
    check->conflict = 1;
  return 0;
}
__clib_export int
egress_policy_vtep_conflict (u32 address)
{
  if (!hash_get (public_addresses, address))
    return 0;
  vtep_check_t check = { .address = address };
  native_walk (check_vtep_flow, &check);
  return check.conflict;
}
static void
resources_collect (void)
{
  if (!collect_resources)
    return;
  resource_mark_t mark = { 0 };
  resource_t *r;
  pool_foreach (r, resources) r->configured = r->live = 0;
  area_t *a;
  vec_foreach (a, areas) mark_area_resources (a, &mark);
  vec_foreach (a, pending) mark_area_resources (a, &mark);
  mark_area_resources (&staged, &mark);
  native_walk (mark_flow_resource, &mark);
  collect_resources = 0;
  u32 *remove = 0, *index;
  pool_foreach (r, resources)
  {
    if (!r->configured && !r->live)
      vec_add1 (remove, (u32)(r - resources));
    if (!r->configured && r->live)
      collect_resources = 1;
  }
  vec_foreach (index, remove)
  {
    r = pool_elt_at_index (resources, *index);
    fib_table_flush (r->fib, FIB_PROTOCOL_IP4, FIB_SOURCE_CLI);
    ip_table_delete (FIB_PROTOCOL_IP4, r->table, 0);
    hash_unset_mem_free (&resource_by_path, &r->key);
    hash_unset (resource_by_fib, r->fib);
    vec_add1 (free_resource_tables, r->table);
    pool_put (resources, r);
  }
  vec_reset_length (remove);
  uword address, unused;
  hash_foreach (address, unused, public_addresses, {
    uword *keep = hash_get (mark.addresses, address);
    if (!keep)
      vec_add1 (remove, (u32)address);
    else if (keep[0] == 2)
      collect_resources = 1;
  });
  vec_foreach (index, remove)
  {
    ip4_address_t addr = { .as_u32 = *index };
    ALWAYS_ASSERT (!native_address (addr, 0));
    hash_unset (public_addresses, *index);
  }
  vec_reset_length (remove);
  uword sw;
  hash_foreach (sw, unused, outside_interfaces, {
    u8 keep = 0;
    pool_foreach (r, resources) if (r->key.sw == sw)
    {
      keep = 1;
      break;
    }
    if (!keep)
      vec_add1 (remove, (u32)sw);
  });
  vec_foreach (index, remove)
  {
    ALWAYS_ASSERT (!native_outside (*index, 0));
    hash_unset (outside_interfaces, *index);
  }
  vec_free (remove);
  hash_free (mark.addresses);
}

/* Runs inside the same worker barrier as publication. Recoverable preparation
 * failures undo only newly prepared resources before any worker resumes. */
static clib_error_t *
resources_prepare (void)
{
  u32 *added_interfaces = 0;
  ip4_address_t *added_addresses = 0;
  area_t *a;
  exit_pool_t *p;
  int rv = 0;
  vec_foreach (a, pending) vec_foreach (p, a->pools)
  {
    resource_t *r = &resources[hash_get (resource_by_fib, p->fib)[0]];
    if (!hash_get (outside_interfaces, r->key.sw))
      {
        if ((rv = native_outside (r->key.sw, 1)))
          goto fail;
        hash_set (outside_interfaces, r->key.sw, 1);
        vec_add1 (added_interfaces, r->key.sw);
      }
    ip4_address_t *addr;
    vec_foreach (addr, p->addresses) if (!hash_get (public_addresses, addr->as_u32))
    {
      if ((rv = native_address (*addr, 1)))
        goto fail;
      hash_set (public_addresses, addr->as_u32, 1);
      vec_add1 (added_addresses, *addr);
    }
  }
  vec_free (added_interfaces);
  vec_free (added_addresses);
  return 0;
fail:
  ip4_address_t *addr;
  vec_foreach (addr, added_addresses)
  {
    ALWAYS_ASSERT (!native_address (*addr, 0));
    hash_unset (public_addresses, addr->as_u32);
  }
  u32 *sw;
  vec_foreach (sw, added_interfaces)
  {
    ALWAYS_ASSERT (!native_outside (*sw, 0));
    hash_unset (outside_interfaces, *sw);
  }
  vec_free (added_interfaces);
  vec_free (added_addresses);
  return clib_error_return (0, "cannot prepare Pool resources: %d", rv);
}

static void
free_area (area_t *a)
{
  vec_free (a->acl);
  vec_free (a->dnat);
  vec_free (a->routes);
  exit_pool_t *p;
  vec_foreach (p, a->pools) vec_free (p->addresses);
  vec_free (a->pools);
  hash_free (a->pool_by_id);
  clib_memset (a, 0, sizeof (*a));
}
/* Native Pool keys are stable name translations, never array sizes. Packet workers read these
 * hashes under the same publication barrier as their owning configuration. */
static exit_pool_t *
pool_for (area_t *a, u32 id)
{
  uword *index = hash_get (a->pool_by_id, id);
  return a->present && index ? &a->pools[index[0]] : 0;
}
static eg_pool_counter_t *
counter_for (access_t *c, u32 id)
{
  uword *index = hash_get (c->counter_by_id, id);
  return index ? &c->counters[index[0]] : 0;
}
/* Main thread, workers stopped. Retain counts while old mappings exist and
 * reclaim removed Pool counters after their mappings have been revoked. */
static void
sync_counters (access_t *c)
{
  area_t *a = &areas[c->area];
  exit_pool_t *p;
  vec_foreach (p, a->pools) if (!counter_for (c, p->id))
  {
    eg_pool_counter_t count = { .id = p->id };
    hash_set (c->counter_by_id, p->id, vec_len (c->counters));
    vec_add1 (c->counters, count);
  }
  u32 kept = 0;
  for (u32 i = 0; i < vec_len (c->counters); i++)
    if (pool_for (a, c->counters[i].id) || c->counters[i].current)
      c->counters[kept++] = c->counters[i];
  if (kept != vec_len (c->counters))
    {
      vec_set_len (c->counters, kept);
      hash_free (c->counter_by_id);
      for (u32 i = 0; i < kept; i++)
        hash_set (c->counter_by_id, c->counters[i].id, i);
    }
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
acl_allows (const area_t *a, u8 proto, ip4_address_t dst, u16 port)
{
  if (!a->present)
    return 0;
  rule_t *r;
  vec_foreach (r, a->acl) if (matches (r, dst, clib_net_to_host_u16 (port), proto)) return r->allow;
  return 1;
}
static int
select_policy (u32 fib, u8 proto, ip4_address_t dst, u16 port, nat44_ed_policy_decision_t *d)
{
  if (fib >= vec_len (attachments) || !attachments[fib].active || attachments[fib].revoked)
    return -1;
  attachment_t *c = &attachments[fib];
  area_t *a = &areas[access_for (c)->area];
  rule_t *r;
  u8 allowed = 1, selected = 0;
  u32 pool = 0, best = 0;
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
    selected = 1;
    d->backend_addr = r->target;
    if (r->target_port)
      d->backend_port = clib_host_to_net_u16 (r->target_port);
    break;
  }
  if (!selected)
    vec_foreach (r, a->routes)
    {
      if (prefix_matches (r, dst) && (!selected || r->prefix > best))
        {
          pool = r->pool;
          selected = 1;
          best = r->prefix;
        }
    }
  exit_pool_t *p = selected ? pool_for (a, pool) : 0;
  if (!p)
    return -1;
  d->cookie = ((u64)fib << 32) | pool;
  d->addresses = p->addresses;
  d->address_count = vec_len (p->addresses);
  d->tx_fib_index = p->fib;
  d->return_key_fib = p->return_fib;
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
    __atomic_fetch_add (&access_for (&attachments[fib])->policy_denied, 1, __ATOMIC_RELAXED);
  return result;
}
static int
reserve (u64 cookie, u32 thread)
{
  attachment_t *c = &attachments[cookie >> 32];
  u32 id = (u32)cookie;
  access_t *access = access_for (c);
  exit_pool_t *p = pool_for (&areas[access->area], id);
  eg_pool_counter_t *count = counter_for (access, id);
  if (!p || !count)
    return 0;
  u64 limit = p->limit;
  u64 n = __atomic_load_n (&count->current, __ATOMIC_RELAXED);
  for (;;)
    {
      if (limit && n >= limit)
        {
          __atomic_fetch_add (&count->denied, 1, __ATOMIC_RELAXED);
          return 0;
        }
      if (__atomic_compare_exchange_n (&count->current, &n, n + 1, 0, __ATOMIC_RELAXED,
                                       __ATOMIC_RELAXED))
        {
          __atomic_fetch_add (&c->current, 1, __ATOMIC_RELAXED);
          return 1;
        }
    }
}
static void
commit (u64 cookie)
{
  eg_pool_counter_t *count = counter_for (access_for (&attachments[cookie >> 32]), (u32)cookie);
  ALWAYS_ASSERT (count);
  __atomic_fetch_add (&count->created, 1, __ATOMIC_RELAXED);
}
static void
release (u64 cookie, u8 committed)
{
  attachment_t *c = &attachments[cookie >> 32];
  u32 id = (u32)cookie;
  eg_pool_counter_t *count = counter_for (access_for (c), id);
  ALWAYS_ASSERT (count);
  u64 old = __atomic_fetch_sub (&count->current, 1, __ATOMIC_RELAXED);
  ALWAYS_ASSERT (old > 0);
  ALWAYS_ASSERT (__atomic_fetch_sub (&c->current, 1, __ATOMIC_RELAXED) > 0);
  __atomic_fetch_add (committed ? &count->released : &count->rollback, 1, __ATOMIC_RELAXED);
}
static int
path_mtu (u64 cookie, u64 expected, u32 inside, u32 route, ip4_address_t dst, ip4_address_t forward,
          u8 out2in)
{
  if (cookie != NAT44_ED_POLICY_NONE)
    {
      u32 fib = cookie >> 32, id = (u32)cookie;
      if (!managed (fib) || attachments[fib].revoked
          || !counter_for (access_for (&attachments[fib]), id))
        return -1;
      /* A mapping keeps its original route, including after a Pool or route
       * rule selects a different exit for new connections. */
      u64 actual;
      int mtu = resolve_path (route, forward, &actual, 0);
      if (mtu < 0 || actual != expected)
        return -1;
      if (!out2in)
        return mtu;
    }
  if (out2in && return_mtu)
    return return_mtu (inside);
  return 0;
}
__clib_export int
egress_policy_has_area (u32 id)
{
  uword *index = hash_get (area_by_id, id);
  return index && areas[index[0]].present;
}

/* Exported operations run with the worker barrier held by the caller. */
__clib_export int
egress_policy_context_bind (u32 fib, u32 table, u32 area, u32 peer, u32 local, u32 slot)
{
  uword *index = hash_get (area_by_id, area);
  if (!index || !areas[index[0]].present || managed (fib))
    return -1;
  access_key_t key = { peer, local, slot, area };
  uword *found = hash_get_mem (access_by_key, &key);
  u32 ai;
  if (found)
    ai = found[0];
  else
    {
      access_t *access;
      pool_get_zero (accesses, access);
      ai = access - accesses;
      access->key = key;
      access->area = index[0];
      hash_set_mem_alloc (&access_by_key, &key, ai);
      sync_counters (access);
    }
  accesses[ai].references++;
  vec_validate (attachments, fib);
  attachment_t *c = &attachments[fib];
  clib_memset (c, 0, sizeof (*c));
  c->table = table;
  c->access = ai;
  c->active = 1;
  return 0;
}
/* A forwarding version can retire while another return format for the same
 * access still has mappings. Shared quota counters must not delay its cleanup. */
__clib_export u32
egress_policy_context_live (u32 fib)
{
  if (!managed (fib))
    return 0;
  u64 total = __atomic_load_n (&attachments[fib].current, __ATOMIC_RELAXED);
  return total > ~0U ? ~0U : total;
}
__clib_export u32
egress_policy_access_count (void)
{
  return pool_elts (accesses);
}
__clib_export int
egress_policy_context_retire (u32 fib)
{
  if (!managed (fib))
    return 0;
  attachment_t *c = &attachments[fib];
  if (c->current)
    return -1;
  access_t *access = access_for (c);
  ALWAYS_ASSERT (access->references);
  if (!--access->references)
    {
      eg_pool_counter_t *count;
      vec_foreach (count, access->counters) ALWAYS_ASSERT (!count->current);
      vec_free (access->counters);
      hash_free (access->counter_by_id);
      hash_unset_mem_free (&access_by_key, &access->key);
      pool_put (accesses, access);
    }
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
  if (w->area != ~0
      && (!managed (f->inside_fib) || access_for (&attachments[f->inside_fib])->area != w->area))
    return 0;
  if (w->flush)
    return 1;
  if (!managed (f->inside_fib))
    return 0;
  attachment_t *c = &attachments[f->inside_fib];
  area_t *a = &areas[access_for (c)->area];
  u32 pool = (u32)f->cookie;
  if (c->revoked || !pool_for (a, pool)
      || !acl_allows (a, f->proto, f->original_remote, f->original_remote_port))
    return 1;
  u64 actual = 0;
  return resolve_path (f->route_fib, f->backend, &actual, 0) < 0 || actual != f->path_signature;
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
static void
abort_batch (void)
{
  free_area (&staged);
  staging = 0;
  area_t *a;
  vec_foreach (a, pending) free_area (a);
  vec_free (pending);
  batching = 0;
  vlib_main_t *vm = vlib_get_main ();
  vlib_worker_thread_barrier_sync (vm);
  collect_resources = 1;
  resources_collect ();
  vlib_worker_thread_barrier_release (vm);
}
__clib_export clib_error_t *
egress_policy_batch_validate (void)
{
  if (!batching || staging)
    return clib_error_return (0, "incomplete file configuration");
  return resources_prepare ();
}
/* Called by Geneve configuration publication under one worker barrier. Area
 * indexes stay stable so established contexts retain their accounting keys. */
__clib_export u32
egress_policy_batch_publish (void)
{
  area_t *a, *n;
  vec_foreach (a, areas)
  {
    u8 keep = 0;
    vec_foreach (n, pending) if (n->id == a->id)
    {
      keep = 1;
      break;
    }
    if (!keep)
      {
        u32 id = a->id;
        free_area (a);
        a->id = id;
      }
  }
  u8 *referenced = 0;
  if (vec_len (areas))
    vec_validate (referenced, vec_len (areas) - 1);
  attachment_t *context;
  vec_foreach (context, attachments) if (context->active) referenced[access_for (context)->area]
      = 1;
  vec_foreach (n, pending)
  {
    uword *found = hash_get (area_by_id, n->id);
    u32 index = found ? found[0] : vec_len (areas);
    if (!found)
      {
        for (index = 0; index < vec_len (areas); index++)
          if (!areas[index].present && (index >= vec_len (referenced) || !referenced[index]))
            break;
        if (index == vec_len (areas))
          {
            area_t empty = { 0 };
            vec_add1 (areas, empty);
          }
        else
          hash_unset (area_by_id, areas[index].id);
        hash_set (area_by_id, n->id, index);
      }
    free_area (&areas[index]);
    areas[index] = *n;
    clib_memset (n, 0, sizeof (*n));
  }
  vec_free (pending);
  vec_free (referenced);
  batching = 0;
  access_t *access;
  pool_foreach (access, accesses) sync_counters (access);
  walk_t w = { .fib = ~0, .area = ~0 };
  u32 terminated = native_walk (visit, &w);
  pool_foreach (access, accesses) sync_counters (access);
  collect_resources = 1;
  resources_collect ();
  return terminated;
}
static clib_error_t *
config_cmd (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  const char *op = cmd->path + 14;
  if (!strcmp (op, "abort"))
    {
      abort_batch ();
      return 0;
    }
  if (!strcmp (op, "reset"))
    {
      abort_batch ();
      batching = 1;
      return 0;
    }
  if (!strcmp (op, "begin"))
    {
      u32 id;
      if (!unformat (in, "area %u", &id) || id > 0xffffff
          || unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
        return clib_error_return (0, "invalid Area ID");
      if (!batching || staging)
        return clib_error_return (0, "reset batch before staging Areas");
      area_t *old;
      vec_foreach (old, pending) if (old->id == id) return clib_error_return (0, "duplicate Area");
      free_area (&staged);
      staged.id = id;
      staged.present = 1;
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
      vec_foreach (r, staged.routes) if (!pool_for (&staged, r->pool)) return clib_error_return (
          0, "unknown route Pool");
      vec_foreach (r, staged.dnat) if (!pool_for (&staged, r->pool)) return clib_error_return (
          0, "unknown DNAT Pool");
      exit_pool_t *p;
      vec_foreach (p, staged.pools) if (!vec_len (p->addresses)) return clib_error_return (
          0, "Pool requires SNAT addresses");
      u32 id = staged.id;
      vec_add1 (pending, staged);
      clib_memset (&staged, 0, sizeof (staged));
      staging = 0;
      vlib_cli_output (vm, "{\"area\":%u,\"staged\":true}", id);
      return 0;
    }
  if (!strcmp (op, "pool"))
    {
      u32 id = ~0, sw = ~0, return_table = ~0, limit = 0;
      ip4_address_t hop;
      if (!unformat (in, "id %u interface %U next-hop %U return-table %u limit %u", &id,
                     unformat_vnet_sw_interface, vnet_get_main (), &sw, unformat_ip4_address, &hop,
                     &return_table, &limit)
          || unformat_check_input (in) != UNFORMAT_END_OF_INPUT || pool_for (&staged, id))
        return clib_error_return (0, "invalid or duplicate Pool");
      u32 rfi = fib_table_find (FIB_PROTOCOL_IP4, return_table);
      if (rfi == ~0 || sw == ~0 || !hop.as_u32)
        return clib_error_return (0, "unknown Pool interface or return table");
      vlib_worker_thread_barrier_sync (vm);
      u32 fib = resource_get (sw, hop);
      vlib_worker_thread_barrier_release (vm);
      if (fib == ~0)
        return clib_error_return (0, "cannot prepare Pool routing table");
      exit_pool_t p = { .id = id, .present = 1, .fib = fib, .return_fib = rfi, .limit = limit };
      hash_set (staged.pool_by_id, id, vec_len (staged.pools));
      vec_add1 (staged.pools, p);
      return 0;
    }
  if (!strcmp (op, "address"))
    {
      u32 id = ~0;
      ip4_address_t addr;
      if (!unformat (in, "pool %u %U", &id, unformat_ip4_address, &addr) || !addr.as_u32
          || unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
        return clib_error_return (0, "invalid Pool address");
      exit_pool_t *p = pool_for (&staged, id);
      if (!p)
        return clib_error_return (0, "unknown Pool");
      vec_add1 (p->addresses, addr);
      return 0;
    }
  rule_t r = { 0 };
  u32 proto = 0, first = 0, last = 0, target_port = 0;
  if (!unformat (in, "dst %U/%u", unformat_ip4_address, &r.network, &r.prefix) || r.prefix > 32)
    return clib_error_return (0, "invalid destination prefix");
  if (!strcmp (op, "route"))
    {
      if (!unformat (in, "pool %u", &r.pool))
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
              || target_port > 65535 || !r.target.as_u32)
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
EG_CMD (eg_reset, "reset");
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
  access_t *c;
  pool_foreach (c, accesses)
  {
    eg_pool_counter_t *p;
    vec_foreach (p, c->counters)
        vlib_cli_output (vm,
                         "{\"peer\":\"%U\",\"gateway\":\"%U\",\"locator\":%u,\"area\":%u,"
                         "\"pool\":%u,\"current\":%llu,\"created\":%llu,\"released\":%llu,"
                         "\"rollback\":%llu,\"denied\":%llu,\"policy_denied\":%llu}",
                         format_ip4_address, &c->key.peer, format_ip4_address, &c->key.local,
                         c->key.slot, areas[c->area].id, p->id, p->current, p->created, p->released,
                         p->rollback, p->denied, c->policy_denied);
  }
  vlib_worker_thread_barrier_release (vm);
  return 0;
}
VLIB_CLI_COMMAND (eg_stats, static) = { .path = "egress-policy stats",
                                        .short_help = "egress-policy stats",
                                        .function = stats_cmd,
                                        .is_mp_safe = 1 };
static clib_error_t *
summary_cmd (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  typedef struct
  {
    u64 current, created, released, denied;
  } total_t;
  total_t **totals = 0;
  if (!vec_len (areas))
    return 0;
  vec_validate (totals, vec_len (areas) - 1);
  vlib_worker_thread_barrier_sync (vm);
  for (u32 a = 0; a < vec_len (areas); a++)
    if (vec_len (areas[a].pools))
      vec_validate (totals[a], vec_len (areas[a].pools) - 1);
  access_t *c;
  pool_foreach (c, accesses)
  {
    eg_pool_counter_t *p;
    vec_foreach (p, c->counters)
    {
      uword *index = hash_get (areas[c->area].pool_by_id, p->id);
      if (!index)
        continue;
      total_t *t = &totals[c->area][index[0]];
      t->current += p->current;
      t->created += p->created;
      t->released += p->released;
      t->denied += p->denied;
    }
  }
  for (u32 a = 0; a < vec_len (areas); a++)
    {
      for (u32 p = 0; p < vec_len (areas[a].pools); p++)
        {
          total_t *t = &totals[a][p];
          vlib_cli_output (vm,
                           "{\"area\":%u,\"pool\":%u,\"current\":%llu,\"created\":%llu,"
                           "\"released\":%llu,\"denied\":%llu}",
                           areas[a].id, areas[a].pools[p].id, t->current, t->created, t->released,
                           t->denied);
        }
      vec_free (totals[a]);
    }
  vlib_worker_thread_barrier_release (vm);
  vec_free (totals);
  return 0;
}
VLIB_CLI_COMMAND (eg_summary, static) = { .path = "egress-policy summary",
                                          .short_help = "Internal aggregate diagnostics",
                                          .function = summary_cmd,
                                          .is_mp_safe = 1 };
static clib_error_t *
paths_cmd (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  vlib_worker_thread_barrier_sync (vm);
  area_t *area;
  ip4_address_t destination = { 0 };
  vec_foreach (area, areas) for (u32 p = 0; p < vec_len (area->pools); p++)
  {
    u64 path = 0;
    u8 neighbor = 0;
    int mtu = resolve_path (area->pools[p].fib, destination, &path, &neighbor);
    ip4_address_t hop = { .as_u32 = (u32)path };
    vlib_cli_output (vm,
                     "{\"area\":%u,\"pool\":%u,\"route_available\":%s,\"neighbor_resolved\":%s,"
                     "\"interface_index\":%u,\"next_hop\":\"%U\",\"mtu\":%d}",
                     area->id, area->pools[p].id, mtu > 0 ? "true" : "false",
                     neighbor ? "true" : "false", (u32)(path >> 32), format_ip4_address, &hop, mtu);
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
      static f64 last_collection;
      f64 now = vlib_time_now (vm);
      if (collect_resources && now - last_collection >= 1.0)
        {
          resources_collect ();
          last_collection = now;
        }
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
  native_address = vlib_get_plugin_symbol ("nat_plugin.so", "nat44_ed_policy_address");
  native_outside = vlib_get_plugin_symbol ("nat_plugin.so", "nat44_ed_policy_outside");
  access_by_key = hash_create_mem (0, sizeof (access_key_t), sizeof (uword));
  resource_by_path = hash_create_mem (0, sizeof (path_key_t), sizeof (uword));
  if (!reg || !native_walk || !native_expire || !return_mtu || !native_address || !native_outside)
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
