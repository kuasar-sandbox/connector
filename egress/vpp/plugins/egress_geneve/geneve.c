/* SPDX-License-Identifier: Apache-2.0 */
/* Immutable authorized network attachments.
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
  ip4_address_t inner;
  f64 deadline;
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
  u16 port_base, tlv_class;
  u8 locator, tlv_type;
} gp_profile_t;
typedef struct
{
  gp_context_t *contexts;
  gp_profile_t *profiles;
  uword *by_key, *by_peer, *vtep_by_rxlocal;
  u32 *by_sw_if, *by_fib;
  u8 registered[65536];
  u32 max_contexts;
} gp_main_t;
static gp_main_t gm;
extern vlib_node_registration_t gp_input_node, gp_output_node;
static u32 (*gp_nat_live) (u32);
static int (*gp_nat_bind) (u32, u8);
static int (*policy_bind) (u32, u32, u32);
static int (*policy_retire) (u32);
static void (*policy_revoke) (u32);
static u32 (*policy_flush_revoked) (void);
static int (*packet_bind) (u32, u8);

/* Outer fragments are unsupported in version one. Drop before local IPv4
 * reassembly, including non-first fragments which have no UDP port header.
 * The configured local VTEP address owns this UDP-fragment policy. */
VLIB_NODE_FN (gp_outer_guard_node) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u16 next[VLIB_FRAME_SIZE];
  u32 dropped = 0;
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 ni;
      vnet_feature_next (&ni, b);
      ip4_header_t *ip = vlib_buffer_get_current (b);
      if (ip->protocol == IP_PROTOCOL_UDP
          && (clib_net_to_host_u16 (ip->flags_and_fragment_offset) & 0x3fff))
        {
          u64 key = ((u64)vnet_buffer (b)->sw_if_index[VLIB_RX] << 32) | ip->dst_address.as_u32;
          if (hash_get (gm.vtep_by_rxlocal, key))
            {
              ni = 0;
              b->error = node->errors[0];
              dropped++;
            }
        }
      next[i] = ni;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next, frame->n_vectors);
  return frame->n_vectors;
}
static char *gp_guard_errors[] = { "unsupported outer UDP fragments" };
VLIB_REGISTER_NODE (gp_outer_guard_node) = {
  .name = "egress-geneve-outer-guard",
  .vector_size = sizeof (u32),
  .n_errors = 1,
  .error_strings = gp_guard_errors,
  .n_next_nodes = 1,
  .next_nodes = { [0] = "error-drop" },
};
VNET_FEATURE_INIT (gp_outer_guard_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "egress-geneve-outer-guard",
  .runs_before = VNET_FEATURES ("ip4-full-reassembly-feature"),
};

static void
gp_bind_vtep (const gp_key_t *key)
{
  u64 k = ((u64)key->rx_if << 32) | key->local_ip;
  hash_set (gm.vtep_by_rxlocal, k, 1);
  vnet_feature_enable_disable ("ip4-unicast", "egress-geneve-outer-guard", key->rx_if, 1, 0, 0);
}

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
  if (!key.locator && dport >= profile->port_base && (u32)dport < profile->port_base + 4096U)
    {
      key.slot = dport - profile->port_base;
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
  if (key.slot >= 4096)
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
  if ((p[advance] >> 4) != 4)
    goto drop;
  uword *entry = hash_get_mem (gm.by_key, &key);
  if (!entry)
    {
      error = GP_ERR_NO_CONTEXT;
      goto drop;
    }
  gp_context_t *c = pool_elt_at_index (gm.contexts, entry[0]);
  if (c->retired || vlib_time_now (vm) >= c->deadline)
    {
      error = GP_ERR_RETIRED;
      goto drop;
    }
  ip4_header_t *inner = (void *)(p + advance);
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
  .next_nodes = { [GP_DROP] = "error-drop", [GP_IP4] = "ip4-input" },
};

static_always_inline u32
gp_output_one (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b)
{
  u32 sw = vnet_buffer (b)->sw_if_index[VLIB_TX];
  u32 error = GP_ERR_NO_CONTEXT;
  if (sw >= vec_len (gm.by_sw_if) || gm.by_sw_if[sw] == ~0)
    goto drop;
  gp_context_t *c = pool_elt_at_index (gm.contexts, gm.by_sw_if[sw]);
  if (c->retired || vlib_time_now (vm) >= c->deadline)
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
  .n_next_nodes = GP_N_NEXT,
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
  c->udp_dst = key->locator == 0 ? profile->port_base + key->slot : 6081;
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
  gp_bind_vtep (key);
  if (!gm.registered[c->udp_dst])
    {
      udp_register_dst_port (vm, c->udp_dst, gp_input_node.index, 1);
      gm.registered[c->udp_dst] = 1;
    }
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
  pool_put (gm.contexts, c);
}
static clib_error_t *
gp_session_cli (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  gp_key_t key = { 0 };
  gp_profile_t profile = { 0 };
  u32 table = ~0, underlay = 0, bits = 0, mtu = 1500, ttl = 0, base = 50000, tclass = 258,
      ttype = 129;
  ip4_address_t local = { 0 }, peer = { 0 }, inner = { 0 }, gateway = { 0 };
  u8 mac[6] = { 2, 0, 0, 0, 0x80, 1 };
  key.rx_if = ~0;
  vnet_main_t *vnm = vnet_get_main ();
  while (unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (in, "table %u", &table))
        ;
      else if (unformat (in, "underlay-table %u", &underlay))
        ;
      else if (unformat (in, "underlay %U", unformat_vnet_sw_interface, vnm, &key.rx_if))
        ;
      else if (unformat (in, "area %u", &key.area))
        ;
      else if (unformat (in, "slot %u", &key.slot))
        ;
      else if (unformat (in, "generation %u", &key.generation))
        ;
      else if (unformat (in, "bits %u", &bits))
        ;
      else if (unformat (in, "mtu %u", &mtu))
        ;
      else if (unformat (in, "lease %u", &ttl))
        ;
      else if (unformat (in, "port-base %u", &base))
        ;
      else if (unformat (in, "tlv-class %u", &tclass))
        ;
      else if (unformat (in, "tlv-type %u", &ttype))
        ;
      else if (unformat (in, "peer %U", unformat_ip4_address, &peer))
        ;
      else if (unformat (in, "local %U", unformat_ip4_address, &local))
        ;
      else if (unformat (in, "inner %U", unformat_ip4_address, &inner))
        ;
      else if (unformat (in, "gateway %U", unformat_ip4_address, &gateway))
        ;
      else if (unformat (in, "mac %U", unformat_ethernet_address, mac))
        ;
      else if (unformat (in, "locator port"))
        key.locator = 0;
      else if (unformat (in, "locator vni"))
        key.locator = 1;
      else if (unformat (in, "locator tlv"))
        key.locator = 2;
      else if (unformat (in, "encap ether"))
        key.ether = 1;
      else if (unformat (in, "encap ip"))
        key.ether = 0;
      else
        return clib_error_return (0, "invalid session argument");
    }
  u32 hdrlen = 36 + (key.ether ? 14 : 0) + (key.locator == 2 ? 8 : 0);
  if (table == ~0 || key.rx_if == ~0 || !local.as_u32 || !peer.as_u32 || !inner.as_u32
      || !gateway.as_u32 || key.slot >= 4096 || key.area > 0xffffff
      || (key.locator == 1 && key.area > 4095) || bits > 20 || !ttl || ttl > 300
      || mtu < hdrlen + 68 || mtu > 65535 || base < 1024 || base > 61440 || tclass > 65535
      || ttype > 255 || (!key.locator && base <= 6081 && base + 4095 >= 6081))
    return clib_error_return (0, "invalid session bounds");
  key.fenced = key.ether && bits > 0;
  if ((key.fenced && key.generation >= (1U << bits)) || (!key.fenced && key.generation))
    return clib_error_return (0, "invalid generation");
  if (!key.fenced && mac[0] == 2 && mac[1] == 0xfe)
    return clib_error_return (0, "reserved legacy MAC");
  key.local_ip = local.as_u32;
  key.peer_ip = peer.as_u32;
  profile.key = (gp_peer_key_t){ key.rx_if, key.local_ip, key.peer_ip };
  profile.locator = key.locator;
  profile.port_base = base;
  profile.tlv_class = tclass;
  profile.tlv_type = ttype;
  uword *existing = hash_get_mem (gm.by_peer, &profile.key);
  if (existing && clib_memcmp (&gm.profiles[existing[0]], &profile, sizeof (profile)))
    return clib_error_return (0, "peer locator configuration conflicts");
  if (!existing && vec_len (gm.profiles) >= 256)
    return clib_error_return (0, "peer capacity");
  if (pool_elts (gm.contexts) >= gm.max_contexts || hash_get_mem (gm.by_key, &key))
    return clib_error_return (0, "attachment capacity or identity already exists");
  if (fib_table_find (FIB_PROTOCOL_IP4, table) != ~0)
    return clib_error_return (0, "table already exists");
  u32 ufi = fib_table_find (FIB_PROTOCOL_IP4, underlay);
  if (ufi == ~0)
    return clib_error_return (0, "underlay table does not exist");
  vlib_worker_thread_barrier_sync (vm);
  if (!existing)
    {
      u32 i = vec_len (gm.profiles);
      vec_add1 (gm.profiles, profile);
      hash_set_mem_alloc (&gm.by_peer, &profile.key, i);
    }
  ip_table_create (FIB_PROTOCOL_IP4, table, 0, 1, 0);
  u32 fi = fib_table_find (FIB_PROTOCOL_IP4, table);
  if (fi == ~0)
    {
      vlib_worker_thread_barrier_release (vm);
      return clib_error_return (0, "table creation failed");
    }
  u32 ci = gp_create_context (vm, &key, table, fi, ufi, mtu, mac);
  gp_context_t *c = pool_elt_at_index (gm.contexts, ci);
  c->inner = inner;
  c->deadline = vlib_time_now (vm) + ttl;
  clib_error_t *error = ip4_add_del_interface_address (vm, c->sw_if_index, &gateway, 32, 0);
  u8 bound = 0, policy = 0;
  if (error)
    goto fail;
  fib_prefix_t prefix = { .fp_proto = FIB_PROTOCOL_IP4, .fp_len = 32, .fp_addr.ip4 = inner };
  ip46_address_t hop = { 0 };
  fib_table_entry_update_one_path (fi, &prefix, FIB_SOURCE_CLI, FIB_ENTRY_FLAG_NONE, DPO_PROTO_IP4,
                                   &hop, c->sw_if_index, 0, 1, 0, FIB_ROUTE_PATH_FLAG_NONE);
  if (policy_bind (fi, table, key.area))
    {
      error = clib_error_return (0, "Area is not configured");
      goto fail;
    }
  policy = 1;
  if (ip4_full_reass_enable_disable (c->sw_if_index, 1))
    {
      error = clib_error_return (0, "reassembly enable failed");
      goto fail;
    }
  if (gp_nat_bind (c->sw_if_index, 1))
    {
      error = clib_error_return (0, "NAT interface bind failed");
      goto fail;
    }
  bound = 1;
  if (packet_bind (c->sw_if_index, 1))
    {
      error = clib_error_return (0, "packet normalization failed");
      goto fail;
    }
  /* No packet can resolve this context before the complete policy, routes,
   * native reassembly and NAT interface have been installed. */
  hash_set_mem_alloc (&gm.by_key, &key, ci);
  vlib_worker_thread_barrier_release (vm);
  vlib_cli_output (vm, "{\"table\":%u,\"interface\":%u,\"lease\":%u}", table, c->sw_if_index, ttl);
  return 0;
fail:
  if (bound)
    gp_nat_bind (c->sw_if_index, 0);
  if (policy)
    policy_retire (fi);
  gp_destroy (vm, c);
  vlib_worker_thread_barrier_release (vm);
  return error;
}
VLIB_CLI_COMMAND (gp_session_command, static)
    = { .path = "egress-geneve session",
        .short_help = "egress-geneve session table <id> underlay <if> local <ip> peer <ip> area "
                      "<vni> slot <n> locator port|vni|tlv encap ip|ether bits <n> generation <g> "
                      "inner <ip> gateway <ip> lease <seconds>",
        .function = gp_session_cli,
        .is_mp_safe = 1 };

static clib_error_t *
gp_lifecycle_cli (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  u32 table = ~0, ttl = 0;
  u8 renew = !strcmp (cmd->path, "egress-geneve renew");
  if (!unformat (in, "table %u", &table)
      || (renew && (!unformat (in, "lease %u", &ttl) || !ttl || ttl > 300))
      || unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "invalid lifecycle request");
  u32 fi = fib_table_find (FIB_PROTOCOL_IP4, table);
  if (fi == ~0 || fi >= vec_len (gm.by_fib) || gm.by_fib[fi] == ~0)
    {
      if (renew)
        return clib_error_return (0, "attachment does not exist");
      vlib_cli_output (vm, "{\"table\":%u,\"retired\":true}", table);
      return 0;
    }
  vlib_worker_thread_barrier_sync (vm);
  gp_context_t *c = pool_elt_at_index (gm.contexts, gm.by_fib[fi]);
  if (renew)
    {
      if (c->retired || vlib_time_now (vm) >= c->deadline)
        {
          vlib_worker_thread_barrier_release (vm);
          return clib_error_return (0, "lease already expired");
        }
      c->deadline = vlib_time_now (vm) + ttl;
    }
  else
    {
      c->retired = 1;
      policy_revoke (fi);
      policy_flush_revoked ();
    }
  vlib_worker_thread_barrier_release (vm);
  vlib_cli_output (vm, "{\"table\":%u,\"retiring\":%s}", table, renew ? "false" : "true");
  return 0;
}
VLIB_CLI_COMMAND (gp_renew_command, static)
    = { .path = "egress-geneve renew",
        .short_help = "egress-geneve renew table <id> lease <seconds>",
        .function = gp_lifecycle_cli,
        .is_mp_safe = 1 };
VLIB_CLI_COMMAND (gp_retire_command, static) = { .path = "egress-geneve retire",
                                                 .short_help = "egress-geneve retire table <id>",
                                                 .function = gp_lifecycle_cli,
                                                 .is_mp_safe = 1 };
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
      pool_foreach (c, gm.contexts) if (c->retired || now >= c->deadline)
      {
        c->retired = 1;
        policy_revoke (c->fib_index);
        any = 1;
      }
      if (any)
        policy_flush_revoked ();
      if (any && ip4_reass_fib_retire_ready ())
        {
          pool_foreach (c, gm.contexts) if (c->retired && !gp_nat_live (c->fib_index))
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
  pool_foreach (c, gm.contexts)
  {
    u32 remaining = (u32)(clib_max (0.0, c->deadline - vlib_time_now (vm)) * 1000);
    vlib_cli_output (vm,
                     "{\"table\":%u,\"area\":%u,\"slot\":%u,\"generation\":%u,\"retiring\":%s,"
                     "\"remaining\":%u.%03u,\"rx\":%llu,\"tx\":%llu}",
                     c->table_id, c->key.area, c->key.slot, c->key.generation,
                     c->retired ? "true" : "false", remaining / 1000, remaining % 1000, c->rx,
                     c->tx);
  }
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
  gm.max_contexts = 4096;
  gp_nat_live = vlib_get_plugin_symbol ("nat_plugin.so", "nat44_ed_fib_live_sessions");
  gp_nat_bind = vlib_get_plugin_symbol ("nat_plugin.so", "nat44_ed_interface_bind");
  policy_bind = vlib_get_plugin_symbol ("egress_policy_plugin.so", "egress_policy_context_bind");
  policy_retire
      = vlib_get_plugin_symbol ("egress_policy_plugin.so", "egress_policy_context_retire");
  policy_revoke
      = vlib_get_plugin_symbol ("egress_policy_plugin.so", "egress_policy_context_revoke");
  policy_flush_revoked
      = vlib_get_plugin_symbol ("egress_policy_plugin.so", "egress_policy_flush_revoked");
  packet_bind = vlib_get_plugin_symbol ("egress_packet_plugin.so", "egress_packet_bind");
  if (!gp_nat_live || !gp_nat_bind || !policy_bind || !policy_retire || !policy_revoke
      || !policy_flush_revoked || !packet_bind)
    return clib_error_return (0, "pinned NAT/policy hooks unavailable");
  return 0;
}
VLIB_INIT_FUNCTION (gp_init);
VLIB_PLUGIN_REGISTER ()
    = { .version = VPP_BUILD_VER, .description = "Connector Egress authorized Geneve attachments" };
