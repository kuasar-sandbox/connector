/* SPDX-License-Identifier: Apache-2.0 */
/* Traffic-created network forwarding contexts.
 * One immutable network attachment => one RX interface and one inside FIB.
 * NAT's return FIB chooses this interface; no shared current-MAC lookup.
 */
#include <egress_geneve/geneve.h>
#include <egress_packet/packet.h>
#include <egress_policy/policy.h>
#include <nat/nat44-ed/nat44_ed_policy.h>
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

/* The first four fields are the access identity. The remaining bytes
 * select an immutable return-format version, never another Pool allowance. */
typedef struct
{
  u32 local_ip, peer_ip, area, slot;
  u8 mac[6], ether, pad;
} gp_key_t;
typedef struct
{
  gp_key_t key;
  u32 sw_if_index, hw_if_index, fib_index, underlay_fib, table_id, rx_if;
  u16 udp_dst, inner_mtu, tlv_class;
  u8 tlv_type, locator;
  ip4_address_t next_hop;
  f64 idle_since;
  u8 mac[6], retired, route_held;
  u64 rx, tx;
} gp_context_t;
typedef struct
{
  u32 rx, local, peer, prefix;
} gp_peer_key_t;
typedef struct
{
  gp_peer_key_t key;
  u16 tlv_class;
  u8 locator, tlv_type;
} gp_profile_t;
typedef struct
{
  gp_profile_t profile;
  u32 underlay_fib, mtu, inner_mtu;
  ip4_address_t next_hop;
} gp_attachment_t;
typedef struct
{
  u32 fib, peer;
} gp_route_key_t;
typedef struct
{
  gp_route_key_t key;
  u32 references, rx;
  ip4_address_t hop;
} gp_route_t;
typedef struct
{
  gp_context_t *contexts;
  uword *by_key, *by_peer, *vtep_by_rxlocal, *by_route;
  gp_route_t *routes;
  u64 prefix_lengths;
  u32 *by_sw_if, *by_fib;
  u8 registered[65536], port_dispatch_registered;
  u32 idle_seconds, next_table, discover_queue;
  u32 *free_tables;
  gp_attachment_t *attachments, *pending;
  u8 staging;
  u64 created, reclaimed;
  u32 pending_idle, timeouts[4];
} gp_main_t;
static gp_main_t gm;
extern vlib_node_registration_t gp_input_node, gp_output_node;
static u32 gp_discover (vlib_main_t *, const gp_key_t *, u32, const u8 *);

/* Configured source ranges are a filter, not an identity or a list of
 * provisioned peers. Lookup uses the packet's actual source address. */
static gp_attachment_t *
gp_match (u32 rx, u32 local, u32 peer)
{
  for (int bits = 32; bits >= 0; bits--)
    {
      if (!(gm.prefix_lengths & (1ULL << bits)))
        continue;
      u32 mask = bits ? clib_host_to_net_u32 (~0U << (32 - bits)) : 0;
      gp_peer_key_t key = { rx, local, peer & mask, (u32)bits };
      uword *index = hash_get_mem (gm.by_peer, &key);
      if (index)
        return &gm.attachments[index[0]];
    }
  return 0;
}

extern void ip4_local_source_admit_register (int (*) (vlib_buffer_t *, ip4_header_t *));
static int
gp_admit_routed_peer (vlib_buffer_t *b, ip4_header_t *ip)
{
  if (ip->ip_version_and_header_length != 0x45 || ip->protocol != IP_PROTOCOL_UDP
      || b->current_length < sizeof (*ip) + sizeof (udp_header_t))
    return 0;
  gp_attachment_t *a = gp_match (vnet_buffer (b)->sw_if_index[VLIB_RX], ip->dst_address.as_u32,
                                 ip->src_address.as_u32);
  if (!a)
    return 0;
  udp_header_t *udp = (void *)(ip + 1);
  u16 port = clib_net_to_host_u16 (udp->dst_port);
  return a->profile.locator ? port == 6081 : port != 0;
}

/* A shared physical interface still has disjoint Geneve and SNAT addresses.
 * Local VTEP UDP traffic must reach UDP-local instead of an out2in NAT lookup. */
VLIB_NODE_FN (gp_bypass_node) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u16 nexts[VLIB_FRAME_SIZE];
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 next;
      vnet_feature_next (&next, b);
      ip4_header_t *ip = vlib_buffer_get_current (b);
      u64 local = ((u64)vnet_buffer (b)->sw_if_index[VLIB_RX] << 32) | ip->dst_address.as_u32;
      if (ip->protocol == IP_PROTOCOL_UDP && hash_get (gm.vtep_by_rxlocal, local))
        next = 0;
      nexts[i] = next;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (gp_bypass_node) = {
  .name = "egress-geneve-bypass",
  .vector_size = sizeof (u32),
  .n_next_nodes = 1,
  .next_nodes = { [0] = "ip4-lookup" },
};
VNET_FEATURE_INIT (gp_bypass_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "egress-geneve-bypass",
  .runs_after = VNET_FEATURES ("ip4-full-reassembly-feature"),
  .runs_before = VNET_FEATURES ("nat-pre-out2in", "nat44-out2in-worker-handoff", "nat44-ed-out2in",
                                "egress-packet-id"),
};
static clib_error_t *
gp_ingress (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  u32 sw;
  if (!unformat (in, "%U", unformat_vnet_sw_interface, vnet_get_main (), &sw)
      || unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected admitted interface");
  int rv = vnet_feature_enable_disable ("ip4-unicast", "egress-geneve-bypass", sw, 1, 0, 0);
  return rv ? clib_error_return (0, "cannot enable Geneve demultiplexing: %d", rv) : 0;
}
VLIB_CLI_COMMAND (gp_ingress_cmd, static) = {
  .path = "egress-geneve ingress",
  .short_help = "Internal ingress feature",
  .function = gp_ingress,
};

extern void ip4_icmp_error_source_register (int (*) (u32, ip4_address_t *));
static int
gp_icmp_source (u32 sw, ip4_address_t *source)
{
  if (sw >= vec_len (gm.by_sw_if) || gm.by_sw_if[sw] == ~0U)
    return 0;
  gp_context_t *c = &gm.contexts[gm.by_sw_if[sw]];
  source->as_u32 = c->key.local_ip;
  return 1;
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
  if (len < 8 + optlen + 20)
    {
      error = GP_ERR_SHORT;
      goto drop;
    }
  u32 rx_if = vnet_buffer (b)->sw_if_index[VLIB_RX];
  key.local_ip = outer->dst_address.as_u32;
  key.peer_ip = outer->src_address.as_u32;
  key.area = ((u32)g->vni[0] << 16) | ((u32)g->vni[1] << 8) | g->vni[2];
  u32 peer_host = clib_net_to_host_u32 (key.peer_ip);
  if (!peer_host || peer_host == ~0U || (peer_host >> 24) == 127 || (peer_host >> 28) == 14
      || key.peer_ip == key.local_ip)
    goto drop;
  gp_attachment_t *attachment = gp_match (rx_if, key.local_ip, key.peer_ip);
  if (!attachment)
    {
      error = GP_ERR_NO_CONTEXT;
      goto drop;
    }
  gp_profile_t *profile = &attachment->profile;
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
  if (!profile->locator && dport)
    {
      /* The received UDP locator is opaque to the gateway. */
      key.slot = dport;
      if (has_locator)
        goto drop;
    }
  else if (profile->locator == 2 && dport == 6081 && has_locator)
    {
    }
  else if (profile->locator == 1 && dport == 6081 && !has_locator)
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
      clib_memcpy_fast (key.mac, return_mac, 6);
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
  if ((key.ether && (return_mac[0] & 1)) || !egress_policy_has_area (key.area))
    goto drop;
  uword *entry = hash_get_mem (gm.by_key, &key);
  u32 ci;
  if (!entry)
    {
      /* Interface/FIB publication belongs to the main thread. The first
       * packet is handed off intact, never used as a sandbox lease. */
      if (vm->thread_index)
        return GP_DISCOVER;
      ci = gp_discover (vm, &key, rx_if, return_mac);
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
  u32 optlen = c->locator == 2 ? 8 : 0;
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
  if (c->locator == 1)
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
gp_create_context (vlib_main_t *vm, const gp_key_t *key, u32 table, u32 fi,
                   const gp_attachment_t *a, const u8 *mac)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hdrlen = 36 + (key->ether ? 14 : 0) + (a->profile.locator == 2 ? 8 : 0);
  gp_context_t *c;
  pool_get_zero (gm.contexts, c);
  u32 ci = c - gm.contexts;
  c->key = *key;
  c->fib_index = fi;
  c->underlay_fib = a->underlay_fib;
  c->table_id = table;
  c->rx_if = a->profile.key.rx;
  c->inner_mtu = clib_min (a->inner_mtu, a->mtu - hdrlen);
  c->next_hop.as_u32 = a->next_hop.as_u32 ? a->next_hop.as_u32 : key->peer_ip;
  c->locator = a->profile.locator;
  c->udp_dst = c->locator == 0 ? key->slot : 6081;
  c->tlv_class = a->profile.tlv_class;
  c->tlv_type = a->profile.tlv_type;
  clib_memcpy_fast (c->mac, mac, 6);
  c->hw_if_index = vnet_register_interface (vnm, gp_device_class.index, ci, gp_hw_class.index, ci);
  c->sw_if_index = vnet_get_hw_interface (vnm, c->hw_if_index)->sw_if_index;
  vnet_set_interface_output_node (vnm, c->hw_if_index, gp_output_node.index);
  vec_validate_init_empty (gm.by_sw_if, c->sw_if_index, ~0);
  gm.by_sw_if[c->sw_if_index] = ci;
  vec_validate_init_empty (gm.by_fib, fi, ~0);
  gm.by_fib[fi] = ci;
  ip_table_bind (FIB_PROTOCOL_IP4, c->sw_if_index, table);
  ip4_sw_interface_enable_disable (c->sw_if_index, 1);
  vnet_sw_interface_set_mtu (vnm, c->sw_if_index, c->inner_mtu);
  vnet_sw_interface_set_flags (vnm, c->sw_if_index, VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  return ci;
}

/* One learned return route per actual peer; ranges are never expanded. */
static void
gp_route_ref (gp_context_t *c, u8 add)
{
  gp_route_key_t key = { c->underlay_fib, c->key.peer_ip };
  uword *found = hash_get_mem (gm.by_route, &key);
  gp_route_t *r;
  if (!add)
    {
      if (!c->route_held)
        return;
      c->route_held = 0;
      if (!found)
        return;
      r = &gm.routes[found[0]];
      ALWAYS_ASSERT (r->references);
      if (--r->references)
        return;
      fib_prefix_t p
          = { .fp_proto = FIB_PROTOCOL_IP4, .fp_len = 32, .fp_addr.ip4.as_u32 = key.peer };
      fib_table_entry_delete (key.fib, &p, FIB_SOURCE_CLI);
      hash_unset_mem_free (&gm.by_route, &key);
      pool_put (gm.routes, r);
      return;
    }
  if (found)
    r = &gm.routes[found[0]];
  else
    {
      pool_get_zero (gm.routes, r);
      r->key = key;
      hash_set_mem_alloc (&gm.by_route, &key, r - gm.routes);
    }
  c->route_held = 1;
  r->references++;
  if (r->references == 1 || r->hop.as_u32 != c->next_hop.as_u32 || r->rx != c->rx_if)
    {
      r->hop = c->next_hop;
      r->rx = c->rx_if;
      fib_prefix_t p
          = { .fp_proto = FIB_PROTOCOL_IP4, .fp_len = 32, .fp_addr.ip4.as_u32 = key.peer };
      ip46_address_t hop = { .ip4 = r->hop };
      fib_table_entry_update_one_path (key.fib, &p, FIB_SOURCE_CLI, FIB_ENTRY_FLAG_NONE,
                                       DPO_PROTO_IP4, &hop, r->rx, 0, 1, 0,
                                       FIB_ROUTE_PATH_FLAG_NONE);
    }
}
static void
gp_retire (gp_context_t *c)
{
  c->retired = 1;
  uword *entry = hash_get_mem (gm.by_key, &c->key);
  if (entry && entry[0] == c - gm.contexts)
    hash_unset_mem_free (&gm.by_key, &c->key);
}

/* These helpers are called only on the main thread with workers stopped. */
static void
gp_destroy (vlib_main_t *vm, gp_context_t *c)
{
  gp_route_ref (c, 0);
  ip4_sw_interface_enable_disable (c->sw_if_index, 0);
  egress_packet_bind (c->sw_if_index, 0);
  fib_table_flush (c->fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_CLI);
  vnet_sw_interface_set_flags (vnet_get_main (), c->sw_if_index, 0);
  ip4_full_reass_enable_disable (c->sw_if_index, 0);
  vnet_delete_hw_interface (vnet_get_main (), c->hw_if_index);
  ip_table_delete (FIB_PROTOCOL_IP4, c->table_id, 0);
  gm.by_sw_if[c->sw_if_index] = ~0;
  gm.by_fib[c->fib_index] = ~0;
  gp_retire (c);
  vec_add1 (gm.free_tables, c->table_id);
  pool_put (gm.contexts, c);
  gm.reclaimed++;
}
/* Main-thread allocation; the worker barrier protects all vectors and hashes.
 * Every context holds the return marker learned from its original packet. */
static u32
gp_discover (vlib_main_t *vm, const gp_key_t *key, u32 rx, const u8 *mac)
{
  gp_attachment_t *matched = gp_match (rx, key->local_ip, key->peer_ip);
  if (!matched || !egress_policy_has_area (key->area))
    return ~0;
  gp_attachment_t a = *matched;
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
  u32 ci = gp_create_context (vm, key, table, fi, &a, mac);
  gp_context_t *c = pool_elt_at_index (gm.contexts, ci);
  c->idle_since = vlib_time_now (vm);
  u8 bound = 0, policy = 0;
  /* Return routing covers every inner destination. ICMP source selection
   * uses the outer gateway address without installing an inner local route. */
  fib_prefix_t prefix = { .fp_proto = FIB_PROTOCOL_IP4, .fp_len = 0 };
  ip46_address_t hop = { 0 };
  fib_table_entry_update_one_path (fi, &prefix, FIB_SOURCE_CLI, FIB_ENTRY_FLAG_NONE, DPO_PROTO_IP4,
                                   &hop, c->sw_if_index, 0, 1, 0, FIB_ROUTE_PATH_FLAG_NONE);
  if (egress_policy_context_bind (fi, table, key->area, key->peer_ip, key->local_ip, key->slot))
    goto fail;
  policy = 1;
  if (ip4_full_reass_enable_disable (c->sw_if_index, 1))
    goto fail;
  if (nat44_ed_interface_bind (c->sw_if_index, 1))
    goto fail;
  bound = 1;
  if (egress_packet_bind (c->sw_if_index, 1))
    goto fail;
  gp_route_ref (c, 1);
  hash_set_mem_alloc (&gm.by_key, key, ci);
  gm.created++;
  vlib_worker_thread_barrier_release (vm);
  return ci;
fail:
  if (bound)
    nat44_ed_interface_bind (c->sw_if_index, 0);
  if (policy)
    egress_policy_context_retire (fi);
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
      u32 idle;
      if (!unformat (in, "idle %u udp %u tcp-established %u tcp-transitory %u icmp %u", &idle,
                     &gm.timeouts[0], &gm.timeouts[1], &gm.timeouts[2], &gm.timeouts[3])
          || !idle || unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
        return clib_error_return (0, "invalid inactivity timeout configuration");
      vec_free (gm.pending);
      gm.staging = 1;
      gm.pending_idle = idle;
      return 0;
    }
  if (!gm.staging)
    return clib_error_return (0, "begin configuration first");
  if (!strcmp (op, "commit"))
    {
      vlib_worker_thread_barrier_sync (vm);
      gp_attachment_t *candidate;
      vec_foreach (candidate, gm.pending) if (egress_policy_vtep_conflict (candidate->profile.key.local))
      {
        vlib_worker_thread_barrier_release (vm);
        return clib_error_return (0,
                                  "Geneve gateway address is retained by an existing SNAT mapping");
      }
      clib_error_t *err = egress_policy_batch_validate ();
      if (err)
        {
          vlib_worker_thread_barrier_release (vm);
          return err;
        }
      u32 removed = egress_policy_batch_publish ();
      nat44_ed_policy_timeouts (gm.timeouts[0], gm.timeouts[1], gm.timeouts[2], gm.timeouts[3]);
      gp_attachment_t *old = gm.attachments;
      gm.attachments = gm.pending;
      gm.pending = 0;
      gm.staging = 0;
      gm.idle_seconds = gm.pending_idle;
      hash_free (gm.by_peer);
      hash_free (gm.vtep_by_rxlocal);
      gm.by_peer = hash_create_mem (0, sizeof (gp_peer_key_t), sizeof (uword));
      gm.prefix_lengths = 0;
      gp_attachment_t *a;
      vec_foreach (a, gm.attachments)
      {
        hash_set_mem_alloc (&gm.by_peer, &a->profile.key, a - gm.attachments);
        gm.prefix_lengths |= 1ULL << a->profile.key.prefix;
        u64 local = ((u64)a->profile.key.rx << 32) | a->profile.key.local;
        hash_set (gm.vtep_by_rxlocal, local, 1);
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
        a = gp_match (c->rx_if, c->key.local_ip, c->key.peer_ip);
        u32 hop = a ? (a->next_hop.as_u32 ? a->next_hop.as_u32 : c->key.peer_ip) : 0;
        if (!a || !egress_policy_has_area (c->key.area) || a->profile.locator != c->locator
            || hop != c->next_hop.as_u32
            || (c->locator == 2
                && (a->profile.tlv_class != c->tlv_class || a->profile.tlv_type != c->tlv_type)))
          {
            gp_retire (c);
            egress_policy_context_revoke (c->fib_index);
          }
        else if (!c->retired)
          {
            u32 overhead = 36 + (c->key.ether ? 14 : 0) + (c->locator == 2 ? 8 : 0);
            c->inner_mtu = clib_min (a->inner_mtu, a->mtu - overhead);
            vnet_sw_interface_set_mtu (vnet_get_main (), c->sw_if_index, c->inner_mtu);
          }
      }
      removed += egress_policy_flush_revoked ();
      vec_free (old);
      vlib_worker_thread_barrier_release (vm);
      vlib_cli_output (vm, "{\"committed\":true,\"terminated\":%u}", removed);
      return 0;
    }
  gp_attachment_t a = { 0 };
  u32 underlay = ~0, tclass = 0, ttype = 0;
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
      else if (unformat (in, "peer %U/%u", unformat_ip4_address, &a.profile.key.peer,
                         &a.profile.key.prefix))
        ;
      else if (unformat (in, "next-hop %U", unformat_ip4_address, &a.next_hop))
        ;
      else if (unformat (in, "mtu %u", &a.mtu))
        ;
      else if (unformat (in, "inner-mtu %u", &a.inner_mtu))
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
      else
        return clib_error_return (0, "invalid attachment configuration");
    }
  a.underlay_fib = fib_table_find (FIB_PROTOCOL_IP4, underlay);
  u32 overhead = 50 + (a.profile.locator == 2 ? 8 : 0);
  if (a.profile.key.rx == ~0 || a.underlay_fib == ~0 || !a.profile.key.local
      || a.profile.key.prefix > 32 || a.mtu < overhead + 68 || a.mtu > 65535 || a.inner_mtu < 68
      || a.inner_mtu > 65535 - overhead || tclass > 65535 || ttype > 255)
    return clib_error_return (0, "invalid attachment bounds");
  u32 mask = a.profile.key.prefix ? clib_host_to_net_u32 (~0U << (32 - a.profile.key.prefix)) : 0;
  if (a.profile.key.peer & ~mask)
    return clib_error_return (0, "non-canonical source range");
  a.profile.tlv_class = tclass;
  a.profile.tlv_type = ttype;
  gp_attachment_t *prior;
  vec_foreach (prior, gm.pending) if (prior->profile.key.rx == a.profile.key.rx
                                      && prior->profile.key.local == a.profile.key.local)
  {
    u32 bits = clib_min (prior->profile.key.prefix, a.profile.key.prefix);
    u32 shared = bits ? clib_host_to_net_u32 (~0U << (32 - bits)) : 0;
    if ((prior->profile.key.peer & shared) != (a.profile.key.peer & shared))
      continue;
    gp_attachment_t x = *prior, y = a;
    x.profile.key.peer = y.profile.key.peer = 0;
    x.profile.key.prefix = y.profile.key.prefix = 0;
    if (clib_memcmp (&x, &y, sizeof (x)))
      return clib_error_return (0, "overlapping sources have conflicting ingress settings");
    if (prior->profile.key.prefix == a.profile.key.prefix)
      return 0;
  }
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
            if (egress_policy_context_live (c->fib_index))
              c->idle_since = 0;
            else if (!c->idle_since)
              c->idle_since = now;
            else if (now - c->idle_since >= gm.idle_seconds)
              gp_retire (c);
          }
        if (c->retired)
          {
            egress_policy_context_revoke (c->fib_index);
            any = 1;
          }
      }
      if (any)
        egress_policy_flush_revoked ();
      if (any && ip4_reass_fib_retire_ready ())
        {
          pool_foreach (c, gm.contexts) if (c->retired && !egress_policy_context_live (c->fib_index))
          {
            ip4_full_reass_purge_fib (c->fib_index);
            ip4_sv_reass_purge_fib (c->fib_index);
            if (!egress_policy_context_retire (c->fib_index) && !nat44_ed_interface_bind (c->sw_if_index, 0))
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
    live += egress_policy_context_live (c->fib_index);
  }
  vlib_cli_output (vm,
                   "{\"contexts\":%u,\"retiring\":%u,\"connections\":%llu,\"created\":%llu,"
                   "\"reclaimed\":%llu,\"accesses\":%u}",
                   count, retiring, live, gm.created, gm.reclaimed, egress_policy_access_count ());
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
  ip4_icmp_error_source_register (gp_icmp_source);
  ip4_local_source_admit_register (gp_admit_routed_peer);
  gm.by_key = hash_create_mem (0, sizeof (gp_key_t), sizeof (uword));
  gm.by_peer = hash_create_mem (0, sizeof (gp_peer_key_t), sizeof (uword));
  gm.by_route = hash_create_mem (0, sizeof (gp_route_key_t), sizeof (uword));
  gm.idle_seconds = 1;
  gm.next_table = 1;
  gm.discover_queue = vlib_handoff_alloc_queues (
      &(vlib_handoff_alloc_queues_args_t){ .node_index = gp_input_node.index, .queue_size = 4096 });
  return 0;
}
VLIB_INIT_FUNCTION (gp_init);
VLIB_PLUGIN_REGISTER ()
    = { .version = VPP_BUILD_VER, .description = "Connector Egress automatic Geneve forwarding" };
