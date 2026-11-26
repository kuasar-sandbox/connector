/* SPDX-License-Identifier: Apache-2.0 */
/* Traffic-created network forwarding contexts.
 * One immutable network attachment => one RX interface and one inside FIB.
 * NAT's return FIB chooses this interface; no shared current-MAC lookup.
 */
#include <vlib/unix/plugin.h>
#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/reass/ip4_full_reass.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/plugin/plugin.h>
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/vnet.h>
#include <vpp/app/version.h>
#include <vppinfra/hash.h>

typedef CLIB_PACKED (struct {
  u8 ver_len;
  u8 flags;
  u16 protocol;
  u8 vni[3];
  u8 reserved;
}) gp_geneve_t;

typedef struct
{
  u32 rx_if, local_ip, peer_ip, area, slot, generation;
  u8 locator, ether, fenced, pad;
} gp_key_t;

typedef struct
{
  gp_key_t key;
  u32 sw_if_index, hw_if_index, fib_index, underlay_fib, table_id;
  u16 udp_dst, inner_mtu, tlv_class;
  u8 tlv_type;
  ip4_address_t inner, gateway;
  f64 idle_since;
  u8 mac[6];
  u8 retired;
  u64 rx, tx;
} gp_context_t;

typedef struct
{
  u32 rx, local, peer;
} gp_peer_key_t;
typedef struct
{
  gp_peer_key_t key;
  u16 tlv_class;
  u8 locator, tlv_type, ether, bits;
} gp_profile_t;
typedef struct
{
  gp_peer_key_t peer;
  u32 area;
} gp_area_key_t;
typedef struct
{
  gp_profile_t profile;
  u32 area, underlay_fib, mtu;
  ip4_address_t gateway, next_hop;
} gp_attachment_t;
typedef struct
{
  gp_context_t *contexts;
  gp_profile_t *profiles;
  uword *by_key, *by_peer, *vtep_by_rxlocal;
  u32 *by_sw_if, *by_fib;
  u8 registered[65536], port_dispatch_registered;
  u32 max_contexts, idle_seconds, next_table, discover_queue;
  u32 *free_tables;
  gp_attachment_t *attachments, *pending;
  uword *by_attachment;
  u8 staging;
  u64 created, reclaimed;
  u32 pending_max, pending_idle, timeouts[4];
} gp_main_t;
static gp_main_t gm;
extern vlib_node_registration_t gp_input_node, gp_output_node;
static u32 (*policy_live) (u32);
static void (*nat_timeouts) (u32, u32, u32, u32);
static int (*gp_nat_bind) (u32, u8);
static int (*policy_bind) (u32, u32, u32);
static int (*policy_retire) (u32);
static void (*policy_revoke) (u32);
static u32 (*policy_flush_revoked) (void);
static int (*packet_bind) (u32, u8);
static clib_error_t *(*policy_validate) (void);
static u32 (*policy_publish) (void);
static u32 gp_discover (vlib_main_t *, const gp_key_t *, ip4_address_t, const u8 *);

/* Called only after NAT has selected an immutable inside FIB. Zero = not ours.
 * Main-thread configuration publishes under the worker barrier. */
__clib_export u32
egress_geneve_return_mtu (u32 fib_index)
{
  if (fib_index >= vec_len (gm.by_fib) || gm.by_fib[fib_index] == ~0)
    return 0;
  return pool_elt_at_index (gm.contexts, gm.by_fib[fib_index])->inner_mtu;
}

static u8 *
gp_format_name (u8 *s, va_list *args)
{
  return format (s, "egress_geneve%u", va_arg (*args, u32));
}

static clib_error_t *
gp_admin (vnet_main_t *vnm, u32 hw, u32 flags)
{
  vnet_hw_interface_set_flags (
      vnm, hw, (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
  return 0;
}

VNET_DEVICE_CLASS (gp_device_class) = {
  .name = "Geneve immutable attachment Egress",
  .format_device_name = gp_format_name,
  .admin_up_down_function = gp_admin,
};

VNET_HW_INTERFACE_CLASS (gp_hw_class) = {
  .name = "GeneveEgress",
  .build_rewrite = default_build_rewrite,
  .update_adjacency = default_update_adjacency,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

enum
{
  GP_DROP,
  GP_IP4,
  GP_DISCOVER,
  GP_N_NEXT
};
enum
{
  GP_ERR_OK,
  GP_ERR_SHORT,
  GP_ERR_FORMAT,
  GP_ERR_NO_CONTEXT,
  GP_ERR_RETIRED,
  GP_ERR_HEADROOM,
  GP_N_ERROR
};
static char *gp_errors[]
    = { "accepted",        "short packet",         "invalid Geneve", "unknown immutable context",
        "retired context", "insufficient headroom" };

static_always_inline u32
gp_input_one (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b)
{
  gp_key_t key = {};
  u8 return_mac[6] = { 2, 0, 0, 0, 0x80, 1 };
  u8 *p = vlib_buffer_get_current (b);
  gp_geneve_t *g = (void *)p;
  u32 error = GP_ERR_FORMAT;
  u32 len = b->current_length;
  if (len < sizeof (*g) || b->current_data < 28 - VLIB_BUFFER_PRE_DATA_SIZE)
    {
      error = GP_ERR_SHORT;
      goto drop;
    }
  /* UDP local has already validated the outer IPv4 and UDP lengths. */
  ip4_header_t *outer = (void *)(p - 28);
  udp_header_t *udp = (void *)(p - 8);
  if (outer->ip_version_and_header_length != 0x45 || g->reserved || (g->ver_len & 0xc0)
      || (g->flags & ~0x40))
    goto drop;
  u32 optlen = (g->ver_len & 0x3f) * 4;
  if (optlen > 64 || len < 8 + optlen + 20)
    {
      error = GP_ERR_SHORT;
      goto drop;
    }
  key.rx_if = vnet_buffer (b)->sw_if_index[VLIB_RX];
  key.local_ip = outer->dst_address.as_u32;
  key.peer_ip = outer->src_address.as_u32;
  key.area = ((u32)g->vni[0] << 16) | ((u32)g->vni[1] << 8) | g->vni[2];
  gp_peer_key_t pk = { key.rx_if, key.local_ip, key.peer_ip };
  uword *profile_entry = hash_get_mem (gm.by_peer, &pk);
  if (!profile_entry)
    {
      error = GP_ERR_NO_CONTEXT;
      goto drop;
    }
  gp_profile_t *profile = &gm.profiles[profile_entry[0]];
  u16 dport = clib_net_to_host_u16 (udp->dst_port);
  u8 has_locator = 0, has_critical = 0;
  for (u32 offset = 8; offset < 8 + optlen;)
    {
      if (offset + 4 > 8 + optlen)
        goto drop;
      u8 *o = p + offset;
      u32 olen = 4 + (o[3] & 0x1f) * 4;
      if ((o[3] & 0xe0) || offset + olen > 8 + optlen)
        goto drop;
      if (profile->locator == 2 && o[0] == (profile->tlv_class >> 8)
          && o[1] == (profile->tlv_class & 255) && o[2] == profile->tlv_type)
        {
          if (has_locator || olen != 8 || offset != 8)
            goto drop;
          has_locator = 1;
          key.slot = ((u32)o[4] << 24) | ((u32)o[5] << 16) | ((u32)o[6] << 8) | o[7];
        }
      else if (o[2] & 0x80)
        goto drop;
      has_critical |= (o[2] & 0x80) != 0;
      offset += olen;
    }
  if (!!(g->flags & 0x40) != has_critical)
    goto drop;
  key.locator = profile->locator;
  if (!key.locator && dport)
    {
      /* The received UDP locator is opaque to the gateway. */
      key.slot = dport;
      if (has_locator)
        goto drop;
    }
  else if (key.locator == 2 && dport == 6081 && has_locator)
    {
    }
  else if (key.locator == 1 && dport == 6081 && !has_locator)
    {
      key.slot = key.area >> 12;
      key.area &= 0xfff;
    }
  else
    goto drop;
  u32 advance = 8 + optlen;
  u16 proto = clib_net_to_host_u16 (g->protocol);
  if (proto == 0x6558)
    {
      if (len < advance + 14 + 20)
        {
          error = GP_ERR_SHORT;
          goto drop;
        }
      ethernet_header_t *eth = (void *)(p + advance);
      if (eth->type != clib_host_to_net_u16 (0x0800))
        goto drop;
      key.ether = 1;
      clib_memcpy_fast (return_mac, eth->src_address, 6);
      if (eth->src_address[0] == 0x02 && eth->src_address[1] == 0xfe)
        {
          key.fenced = 1;
          key.generation = ((u32)eth->src_address[2] << 24) | ((u32)eth->src_address[3] << 16)
                           | ((u32)eth->src_address[4] << 8) | eth->src_address[5];
        }
      advance += 14;
    }
  else if (proto != 0x0800)
    goto drop;
  ip4_header_t *inner = (void *)(p + advance);
  u32 ihl = (inner->ip_version_and_header_length & 15) * 4;
  if ((p[advance] >> 4) != 4 || ihl < 20 || len < advance + ihl
      || clib_net_to_host_u16 (inner->length) < ihl
      || vlib_buffer_length_in_chain (vm, b) < advance + clib_net_to_host_u16 (inner->length)
      || !ip4_header_checksum_is_valid (inner) || !inner->src_address.as_u32)
    goto drop;
  if (key.ether != profile->ether || key.fenced != (profile->ether && profile->bits)
      || (key.fenced && key.generation >= (1U << profile->bits))
      || (key.ether && (return_mac[0] & 1)))
    goto drop;
  gp_area_key_t ak = { pk, key.area };
  if (!hash_get_mem (gm.by_attachment, &ak))
    goto drop;
  uword *entry = hash_get_mem (gm.by_key, &key);
  u32 ci;
  if (!entry)
    {
      /* Interface/FIB publication belongs to the main thread. The first
       * packet is handed off intact, never used as a sandbox lease. */
      if (vm->thread_index)
        return GP_DISCOVER;
      ci = gp_discover (vm, &key, inner->src_address, return_mac);
      if (ci == ~0)
        {
          error = GP_ERR_NO_CONTEXT;
          goto drop;
        }
    }
  else
    ci = entry[0];
  gp_context_t *c = pool_elt_at_index (gm.contexts, ci);
  if (c->retired)
    {
      error = GP_ERR_RETIRED;
      goto drop;
    }
  if (inner->src_address.as_u32 != c->inner.as_u32
      || (key.ether && clib_memcmp (return_mac, c->mac, 6)))
    goto drop;
  vlib_buffer_advance (b, advance);
  vnet_buffer (b)->sw_if_index[VLIB_RX] = c->sw_if_index;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
  vnet_buffer (b)->l3_hdr_offset = b->current_data;
  b->flags &= ~(VNET_BUFFER_F_OFFLOAD | VNET_BUFFER_F_L4_CHECKSUM_COMPUTED
                | VNET_BUFFER_F_L4_CHECKSUM_CORRECT);
  b->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
  __atomic_fetch_add (&c->rx, 1, __ATOMIC_RELAXED);
  vlib_node_increment_counter (vm, node->node_index, GP_ERR_OK, 1);
  return GP_IP4;
drop:
  b->error = node->errors[error];
  return GP_DROP;
}

VLIB_NODE_FN (gp_input_node) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u16 next[VLIB_FRAME_SIZE];
  u32 n = 0;
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      u32 bi = from[i];
      u32 ni = gp_input_one (vm, node, vlib_get_buffer (vm, bi));
      if (ni != ~0)
        {
          from[n] = bi;
          next[n++] = ni;
        }
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next, n);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (gp_input_node) = {
  .name = "egress-geneve-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = GP_N_ERROR,
  .error_strings = gp_errors,
  .n_next_nodes = GP_N_NEXT,
  .next_nodes
  = { [GP_DROP] = "error-drop", [GP_IP4] = "ip4-input", [GP_DISCOVER] = "egress-geneve-discover" },
};

VLIB_NODE_FN (gp_discover_node) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u16 threads[VLIB_FRAME_SIZE] = { 0 };
  vlib_buffer_enqueue_to_thread (vm, node, gm.discover_queue, vlib_frame_vector_args (frame),
                                 threads, frame->n_vectors);
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (gp_discover_node) = {
  .name = "egress-geneve-discover",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

static_always_inline u32
gp_output_one (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b)
{
  u32 sw = vnet_buffer (b)->sw_if_index[VLIB_TX];
  u32 error = GP_ERR_NO_CONTEXT;
  if (sw >= vec_len (gm.by_sw_if) || gm.by_sw_if[sw] == ~0)
    goto drop;
  gp_context_t *c = pool_elt_at_index (gm.contexts, gm.by_sw_if[sw]);
  if (c->retired)
    {
      error = GP_ERR_RETIRED;
      goto drop;
    }
  u32 optlen = c->key.locator == 2 ? 8 : 0;
  u32 hdrlen = 20 + 8 + 8 + optlen + (c->key.ether ? 14 : 0);
  if (b->current_data - (i32)hdrlen < -VLIB_BUFFER_PRE_DATA_SIZE)
    {
      error = GP_ERR_HEADROOM;
      goto drop;
    }
  u32 inner_len = vlib_buffer_length_in_chain (vm, b);
  /* Inner rewrite must already have fragmented non-DF packets; never emit
   * outer fragments, which the connector return dataplane cannot reassemble. */
  if (inner_len > c->inner_mtu)
    {
      error = GP_ERR_FORMAT;
      goto drop;
    }
  u32 total = inner_len + hdrlen;
  if (total > 65535)
    {
      error = GP_ERR_FORMAT;
      goto drop;
    }
  vlib_buffer_advance (b, -(i32)hdrlen);
  u8 *p = vlib_buffer_get_current (b);
  clib_memset (p, 0, hdrlen);
  ip4_header_t *ip = (void *)p;
  udp_header_t *udp = (void *)(p + 20);
  gp_geneve_t *g = (void *)(p + 28);
  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  ip4_header_set_df (ip);
  ip->length = clib_host_to_net_u16 (total);
  ip->src_address.as_u32 = c->key.local_ip;
  ip->dst_address.as_u32 = c->key.peer_ip;
  ip->checksum = ip4_header_checksum (ip);
  udp->src_port = clib_host_to_net_u16 (6081);
  udp->dst_port = clib_host_to_net_u16 (c->udp_dst);
  udp->length = clib_host_to_net_u16 (total - 20);
  g->ver_len = optlen / 4;
  g->flags = optlen && (c->tlv_type & 0x80) ? 0x40 : 0;
  g->protocol = clib_host_to_net_u16 (c->key.ether ? 0x6558 : 0x0800);
  u32 vni = c->key.area;
  if (c->key.locator == 1)
    vni |= c->key.slot << 12;
  g->vni[0] = vni >> 16;
  g->vni[1] = vni >> 8;
  g->vni[2] = vni;
  if (optlen)
    {
      u8 *o = p + 36;
      o[0] = c->tlv_class >> 8;
      o[1] = c->tlv_class;
      o[2] = c->tlv_type;
      o[3] = 1;
      o[4] = c->key.slot >> 24;
      o[5] = c->key.slot >> 16;
      o[6] = c->key.slot >> 8;
      o[7] = c->key.slot;
    }
  if (c->key.ether)
    {
      ethernet_header_t *eth = (void *)(p + 36 + optlen);
      clib_memcpy_fast (eth->dst_address, c->mac, 6);
      u8 source[6] = { 2, 0, 0, 0, 0, 1 };
      clib_memcpy_fast (eth->src_address, source, 6);
      eth->type = clib_host_to_net_u16 (0x0800);
    }
  b->flags &= ~(VNET_BUFFER_F_OFFLOAD | VNET_BUFFER_F_L4_CHECKSUM_COMPUTED
                | VNET_BUFFER_F_L4_CHECKSUM_CORRECT);
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED | VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
  vnet_buffer (b)->l3_hdr_offset = b->current_data;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = c->underlay_fib;
  __atomic_fetch_add (&c->tx, 1, __ATOMIC_RELAXED);
  vlib_node_increment_counter (vm, node->node_index, GP_ERR_OK, 1);
  return GP_IP4;
drop:
  b->error = node->errors[error];
  return GP_DROP;
}

VLIB_NODE_FN (gp_output_node) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u16 next[VLIB_FRAME_SIZE];
  for (u32 i = 0; i < frame->n_vectors; i++)
    next[i] = gp_output_one (vm, node, vlib_get_buffer (vm, from[i]));
  vlib_buffer_enqueue_to_next (vm, node, from, next, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (gp_output_node) = {
  .name = "egress-geneve-output",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = GP_N_ERROR,
  .error_strings = gp_errors,
  .n_next_nodes = GP_IP4 + 1,
  .next_nodes = { [GP_DROP] = "error-drop", [GP_IP4] = "ip4-lookup" },
};

static u32
gp_create_context (vlib_main_t *vm, const gp_key_t *key, u32 table, u32 fi, u32 ufi, u32 mtu,
                   const u8 *mac)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hdrlen = 36 + (key->ether ? 14 : 0) + (key->locator == 2 ? 8 : 0);
  gp_context_t *c;
  pool_get_zero (gm.contexts, c);
  u32 ci = c - gm.contexts;
  c->key = *key;
  c->fib_index = fi;
  c->underlay_fib = ufi;
  c->table_id = table;
  c->inner_mtu = mtu - hdrlen;
  gp_peer_key_t pk = { key->rx_if, key->local_ip, key->peer_ip };
  gp_profile_t *profile = &gm.profiles[hash_get_mem (gm.by_peer, &pk)[0]];
  c->udp_dst = key->locator == 0 ? key->slot : 6081;
  c->tlv_class = profile->tlv_class;
  c->tlv_type = profile->tlv_type;
  clib_memcpy_fast (c->mac, mac, 6);
  if (key->fenced)
    {
      c->mac[0] = 2;
      c->mac[1] = 0xfe;
      c->mac[2] = key->generation >> 24;
      c->mac[3] = key->generation >> 16;
      c->mac[4] = key->generation >> 8;
      c->mac[5] = key->generation;
    }
  c->hw_if_index = vnet_register_interface (vnm, gp_device_class.index, ci, gp_hw_class.index, ci);
  c->sw_if_index = vnet_get_hw_interface (vnm, c->hw_if_index)->sw_if_index;
  vnet_set_interface_output_node (vnm, c->hw_if_index, gp_output_node.index);
  vec_validate_init_empty (gm.by_sw_if, c->sw_if_index, ~0);
  gm.by_sw_if[c->sw_if_index] = ci;
  vec_validate_init_empty (gm.by_fib, fi, ~0);
  gm.by_fib[fi] = ci;
  ip_table_bind (FIB_PROTOCOL_IP4, c->sw_if_index, table);
  vnet_sw_interface_set_mtu (vnm, c->sw_if_index, c->inner_mtu);
  vnet_sw_interface_set_flags (vnm, c->sw_if_index, VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  return ci;
}

/* These helpers are called only on the main thread with workers stopped. */
static void
gp_destroy (vlib_main_t *vm, gp_context_t *c)
{
  packet_bind (c->sw_if_index, 0);
  fib_table_flush (c->fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_CLI);
  vnet_sw_interface_set_flags (vnet_get_main (), c->sw_if_index, 0);
  ip4_full_reass_enable_disable (c->sw_if_index, 0);
  vnet_delete_hw_interface (vnet_get_main (), c->hw_if_index);
  ip_table_delete (FIB_PROTOCOL_IP4, c->table_id, 0);
  gm.by_sw_if[c->sw_if_index] = ~0;
  gm.by_fib[c->fib_index] = ~0;
  if (hash_get_mem (gm.by_key, &c->key))
    hash_unset_mem_free (&gm.by_key, &c->key);
  vec_add1 (gm.free_tables, c->table_id);
  pool_put (gm.contexts, c);
  gm.reclaimed++;
}
/* Main-thread allocation; the worker barrier protects all vectors and hashes.
 * Every context holds the return marker learned from its original packet. */
static u32
gp_discover (vlib_main_t *vm, const gp_key_t *key, ip4_address_t inner, const u8 *mac)
{
  gp_area_key_t ak = { { key->rx_if, key->local_ip, key->peer_ip }, key->area };
  uword *found = hash_get_mem (gm.by_attachment, &ak);
  if (!found || pool_elts (gm.contexts) >= gm.max_contexts)
    return ~0;
  gp_attachment_t a = gm.attachments[found[0]];
  if (inner.as_u32 == a.gateway.as_u32)
    return ~0;
  vlib_worker_thread_barrier_sync (vm);
  /* Physical interfaces and exits share VPP's table-ID namespace. Allocate a
   * free ID instead of reserving fixed numeric ranges for object classes. */
  u32 table;
  do
    {
      table = vec_len (gm.free_tables) ? vec_pop (gm.free_tables) : gm.next_table++;
      if (gm.next_table == ~0U)
        gm.next_table = 1;
    }
  while (!table || table == ~0U || fib_table_find (FIB_PROTOCOL_IP4, table) != ~0U);
  ip_table_create (FIB_PROTOCOL_IP4, table, 0, 1, 0);
  u32 fi = fib_table_find (FIB_PROTOCOL_IP4, table);
  if (fi == ~0)
    {
      vlib_worker_thread_barrier_release (vm);
      return ~0;
    }
  u32 ci = gp_create_context (vm, key, table, fi, a.underlay_fib, a.mtu, mac);
  gp_context_t *c = pool_elt_at_index (gm.contexts, ci);
  c->inner = inner;
  c->gateway = a.gateway;
  c->idle_since = vlib_time_now (vm);
  clib_error_t *error = ip4_add_del_interface_address (vm, c->sw_if_index, &a.gateway, 32, 0);
  u8 bound = 0, policy = 0;
  if (error)
    goto fail;
  fib_prefix_t prefix = { .fp_proto = FIB_PROTOCOL_IP4, .fp_len = 32, .fp_addr.ip4 = inner };
  ip46_address_t hop = { 0 };
  fib_table_entry_update_one_path (fi, &prefix, FIB_SOURCE_CLI, FIB_ENTRY_FLAG_NONE, DPO_PROTO_IP4,
                                   &hop, c->sw_if_index, 0, 1, 0, FIB_ROUTE_PATH_FLAG_NONE);
  if (policy_bind (fi, table, key->area))
    goto fail;
  policy = 1;
  if (ip4_full_reass_enable_disable (c->sw_if_index, 1))
    goto fail;
  if (gp_nat_bind (c->sw_if_index, 1))
    goto fail;
  bound = 1;
  if (packet_bind (c->sw_if_index, 1))
    goto fail;
  hash_set_mem_alloc (&gm.by_key, key, ci);
  gm.created++;
  vlib_worker_thread_barrier_release (vm);
  return ci;
fail:
  if (error)
    clib_error_free (error);
  if (bound)
    gp_nat_bind (c->sw_if_index, 0);
  if (policy)
    policy_retire (fi);
  gp_destroy (vm, c);
  vlib_worker_thread_barrier_release (vm);
  return ~0;
}

static clib_error_t *
gp_configuration (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  const char *op = cmd->path + 14;
  if (!strcmp (op, "abort"))
    {
      vec_free (gm.pending);
      gm.staging = 0;
      return 0;
    }
  if (!strcmp (op, "begin"))
    {
      u32 count, idle;
      if (!unformat (
              in, "max-contexts %u idle %u udp %u tcp-established %u tcp-transitory %u icmp %u",
              &count, &idle, &gm.timeouts[0], &gm.timeouts[1], &gm.timeouts[2], &gm.timeouts[3])
          || !count || !idle || unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
        return clib_error_return (0, "invalid context resource budget");
      vec_free (gm.pending);
      gm.staging = 1;
      gm.pending_max = count;
      gm.pending_idle = idle;
      return 0;
    }
  if (!gm.staging)
    return clib_error_return (0, "begin configuration first");
  if (!strcmp (op, "commit"))
    {
      clib_error_t *err = policy_validate ();
      if (err)
        return err;
      vlib_worker_thread_barrier_sync (vm);
      u32 removed = policy_publish ();
      nat_timeouts (gm.timeouts[0], gm.timeouts[1], gm.timeouts[2], gm.timeouts[3]);
      gp_attachment_t *old = gm.attachments;
      gm.attachments = gm.pending;
      gm.pending = 0;
      gm.staging = 0;
      gm.max_contexts = gm.pending_max;
      gm.idle_seconds = gm.pending_idle;
      hash_free (gm.by_peer);
      hash_free (gm.by_attachment);
      gm.by_peer = hash_create_mem (0, sizeof (gp_peer_key_t), sizeof (uword));
      gm.by_attachment = hash_create_mem (0, sizeof (gp_area_key_t), sizeof (uword));
      vec_reset_length (gm.profiles);
      gp_attachment_t *a;
      /* Peer routes and all profiles change under the same publication barrier. */
      vec_foreach (a, old)
      {
        fib_prefix_t p = { .fp_proto = FIB_PROTOCOL_IP4,
                           .fp_len = 32,
                           .fp_addr.ip4.as_u32 = a->profile.key.peer };
        fib_table_entry_delete (a->underlay_fib, &p, FIB_SOURCE_CLI);
      }
      vec_foreach (a, gm.attachments)
      {
        if (!hash_get_mem (gm.by_peer, &a->profile.key))
          {
            hash_set_mem_alloc (&gm.by_peer, &a->profile.key, vec_len (gm.profiles));
            vec_add1 (gm.profiles, a->profile);
          }
        fib_prefix_t p = { .fp_proto = FIB_PROTOCOL_IP4,
                           .fp_len = 32,
                           .fp_addr.ip4.as_u32 = a->profile.key.peer };
        ip46_address_t hop = { .ip4 = a->next_hop };
        fib_table_entry_update_one_path (a->underlay_fib, &p, FIB_SOURCE_CLI, FIB_ENTRY_FLAG_NONE,
                                         DPO_PROTO_IP4, &hop, a->profile.key.rx, 0, 1, 0,
                                         FIB_ROUTE_PATH_FLAG_NONE);
        gp_area_key_t ak = { a->profile.key, a->area };
        hash_set_mem_alloc (&gm.by_attachment, &ak, a - gm.attachments);
        if (!a->profile.locator && gm.port_dispatch_registered)
          continue;
        u32 start = a->profile.locator ? 6081 : 1;
        u32 end = a->profile.locator ? start + 1 : 65536;
        if (!a->profile.locator)
          gm.port_dispatch_registered = 1;
        for (u32 port = start; port < end; port++)
          if (!gm.registered[port])
            {
              udp_register_dst_port (vm, port, gp_input_node.index, 1);
              gm.registered[port] = 1;
            }
      }
      gp_context_t *c;
      pool_foreach (c, gm.contexts)
      {
        gp_area_key_t ak = { { c->key.rx_if, c->key.local_ip, c->key.peer_ip }, c->key.area };
        uword *f = hash_get_mem (gm.by_attachment, &ak);
        if (!f)
          {
            c->retired = 1;
            policy_revoke (c->fib_index);
            continue;
          }
        a = &gm.attachments[f[0]];
        if (a->profile.locator != c->key.locator || a->profile.ether != c->key.ether
            || a->gateway.as_u32 != c->gateway.as_u32
            || (c->key.locator == 2
                && (a->profile.tlv_class != c->tlv_class || a->profile.tlv_type != c->tlv_type))
            || (a->profile.ether && a->profile.bits > 0) != c->key.fenced
            || (c->key.fenced && c->key.generation >= (1U << a->profile.bits)))
          {
            c->retired = 1;
            policy_revoke (c->fib_index);
          }
        else
          {
            c->inner_mtu = a->mtu - 36 - (c->key.ether ? 14 : 0) - (c->key.locator == 2 ? 8 : 0);
            vnet_sw_interface_set_mtu (vnet_get_main (), c->sw_if_index, c->inner_mtu);
            c->tlv_class = a->profile.tlv_class;
            c->tlv_type = a->profile.tlv_type;
          }
      }
      removed += policy_flush_revoked ();
      vec_free (old);
      vlib_worker_thread_barrier_release (vm);
      vlib_cli_output (vm, "{\"committed\":true,\"terminated\":%u}", removed);
      return 0;
    }
  gp_attachment_t a = { 0 };
  u32 underlay = ~0, bits = 0, base = 50000, tclass = 258, ttype = 129;
  a.profile.key.rx = ~0;
  while (unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (in, "underlay %U", unformat_vnet_sw_interface, vnet_get_main (),
                    &a.profile.key.rx))
        ;
      else if (unformat (in, "underlay-table %u", &underlay))
        ;
      else if (unformat (in, "local %U", unformat_ip4_address, &a.profile.key.local))
        ;
      else if (unformat (in, "peer %U", unformat_ip4_address, &a.profile.key.peer))
        ;
      else if (unformat (in, "next-hop %U", unformat_ip4_address, &a.next_hop))
        ;
      else if (unformat (in, "area %u", &a.area))
        ;
      else if (unformat (in, "gateway %U", unformat_ip4_address, &a.gateway))
        ;
      else if (unformat (in, "mtu %u", &a.mtu))
        ;
      else if (unformat (in, "bits %u", &bits))
        ;
      else if (unformat (in, "port-base %u", &base))
        ;
      else if (unformat (in, "tlv-class %u", &tclass))
        ;
      else if (unformat (in, "tlv-type %u", &ttype))
        ;
      else if (unformat (in, "locator port"))
        a.profile.locator = 0;
      else if (unformat (in, "locator vni"))
        a.profile.locator = 1;
      else if (unformat (in, "locator tlv"))
        a.profile.locator = 2;
      else if (unformat (in, "encap ether"))
        a.profile.ether = 1;
      else if (unformat (in, "encap ip"))
        a.profile.ether = 0;
      else
        return clib_error_return (0, "invalid attachment configuration");
    }
  a.underlay_fib = fib_table_find (FIB_PROTOCOL_IP4, underlay);
  u32 overhead = 36 + (a.profile.ether ? 14 : 0) + (a.profile.locator == 2 ? 8 : 0);
  if (a.profile.key.rx == ~0 || a.underlay_fib == ~0 || !a.profile.key.local || !a.profile.key.peer
      || !a.gateway.as_u32 || !a.next_hop.as_u32 || a.area > 0xffffff
      || (a.profile.locator == 1 && a.area > 4095) || bits > 20 || a.mtu < overhead + 68
      || a.mtu > 65535 || base > 65535 || tclass > 65535 || ttype > 255)
    return clib_error_return (0, "invalid attachment bounds");
  a.profile.bits = bits;
  a.profile.tlv_class = tclass;
  a.profile.tlv_type = ttype;
  gp_attachment_t *prior;
  vec_foreach (prior, gm.pending) if (
      !clib_memcmp (&prior->profile.key, &a.profile.key, sizeof (gp_peer_key_t))
      && (prior->area == a.area
          || clib_memcmp (
              &prior->profile, &a.profile,
              sizeof (gp_profile_t)))) return clib_error_return (0, "duplicate or inconsistent "
                                                                    "attachment");
  vec_add1 (gm.pending, a);
  return 0;
}
#define GP_CONFIG(symbol, operation)                                                               \
  VLIB_CLI_COMMAND (symbol, static) = { .path = "egress-geneve " operation,                        \
                                        .short_help = "Internal file configuration: " operation,   \
                                        .function = gp_configuration,                              \
                                        .is_mp_safe = 1 }
GP_CONFIG (gp_begin, "begin");
GP_CONFIG (gp_abort, "abort");
GP_CONFIG (gp_profile, "profile");
GP_CONFIG (gp_commit, "commit");

static uword
gp_reaper (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  uword *events = 0;
  u32 *expired = 0, *i;
  gp_context_t *c;
  for (;;)
    {
      vlib_process_wait_for_event_or_clock (vm, 0.1);
      vlib_process_get_events (vm, &events);
      vec_reset_length (events);
      f64 now = vlib_time_now (vm);
      u8 any = 0;
      vlib_worker_thread_barrier_sync (vm);
      pool_foreach (c, gm.contexts)
      {
        if (!c->retired)
          {
            if (policy_live (c->fib_index))
              c->idle_since = 0;
            else if (!c->idle_since)
              c->idle_since = now;
            else if (now - c->idle_since >= gm.idle_seconds)
              c->retired = 1;
          }
        if (c->retired)
          {
            policy_revoke (c->fib_index);
            any = 1;
          }
      }
      if (any)
        policy_flush_revoked ();
      if (any && ip4_reass_fib_retire_ready ())
        {
          pool_foreach (c, gm.contexts) if (c->retired && !policy_live (c->fib_index))
          {
            ip4_full_reass_purge_fib (c->fib_index);
            ip4_sv_reass_purge_fib (c->fib_index);
            if (!policy_retire (c->fib_index) && !gp_nat_bind (c->sw_if_index, 0))
              vec_add1 (expired, (u32)(c - gm.contexts));
          }
          vec_foreach (i, expired) gp_destroy (vm, pool_elt_at_index (gm.contexts, *i));
          vec_reset_length (expired);
        }
      vlib_worker_thread_barrier_release (vm);
    }
  return 0;
}
VLIB_REGISTER_NODE (gp_reaper_node)
    = { .function = gp_reaper, .type = VLIB_NODE_TYPE_PROCESS, .name = "egress-attachment-reaper" };
static clib_error_t *
gp_show_cli (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  gp_context_t *c;
  vlib_worker_thread_barrier_sync (vm);
  u32 count = 0, retiring = 0;
  u64 live = 0;
  pool_foreach (c, gm.contexts)
  {
    count++;
    retiring += !!c->retired;
    live += policy_live (c->fib_index);
  }
  vlib_cli_output (vm,
                   "{\"contexts\":%u,\"retiring\":%u,\"connections\":%llu,\"created\":%llu,"
                   "\"reclaimed\":%llu,\"capacity\":%u}",
                   count, retiring, live, gm.created, gm.reclaimed, gm.max_contexts);
  vlib_worker_thread_barrier_release (vm);
  return 0;
}
VLIB_CLI_COMMAND (gp_show_command, static) = { .path = "show egress-geneve",
                                               .short_help = "show egress-geneve",
                                               .function = gp_show_cli,
                                               .is_mp_safe = 1 };
static clib_error_t *
gp_init (vlib_main_t *vm)
{
  gm.by_key = hash_create_mem (0, sizeof (gp_key_t), sizeof (uword));
  gm.by_peer = hash_create_mem (0, sizeof (gp_peer_key_t), sizeof (uword));
  gm.by_attachment = hash_create_mem (0, sizeof (gp_area_key_t), sizeof (uword));
  gm.max_contexts = 65536;
  gm.idle_seconds = 1;
  gm.next_table = 1;
  gm.discover_queue = vlib_handoff_alloc_queues (
      &(vlib_handoff_alloc_queues_args_t){ .node_index = gp_input_node.index, .queue_size = 4096 });
  policy_live = vlib_get_plugin_symbol ("egress_policy_plugin.so", "egress_policy_context_live");
  policy_validate
      = vlib_get_plugin_symbol ("egress_policy_plugin.so", "egress_policy_batch_validate");
  policy_publish
      = vlib_get_plugin_symbol ("egress_policy_plugin.so", "egress_policy_batch_publish");
  nat_timeouts = vlib_get_plugin_symbol ("nat_plugin.so", "nat44_ed_policy_timeouts");
  gp_nat_bind = vlib_get_plugin_symbol ("nat_plugin.so", "nat44_ed_interface_bind");
  policy_bind = vlib_get_plugin_symbol ("egress_policy_plugin.so", "egress_policy_context_bind");
  policy_retire
      = vlib_get_plugin_symbol ("egress_policy_plugin.so", "egress_policy_context_retire");
  policy_revoke
      = vlib_get_plugin_symbol ("egress_policy_plugin.so", "egress_policy_context_revoke");
  policy_flush_revoked
      = vlib_get_plugin_symbol ("egress_policy_plugin.so", "egress_policy_flush_revoked");
  packet_bind = vlib_get_plugin_symbol ("egress_packet_plugin.so", "egress_packet_bind");
  if (!nat_timeouts || !policy_live || !policy_validate || !policy_publish || !gp_nat_bind
      || !policy_bind || !policy_retire || !policy_revoke || !policy_flush_revoked || !packet_bind)
    return clib_error_return (0, "pinned NAT/policy hooks unavailable");
  return 0;
}
VLIB_INIT_FUNCTION (gp_init);
VLIB_PLUGIN_REGISTER ()
    = { .version = VPP_BUILD_VER, .description = "Connector Egress automatic Geneve forwarding" };
