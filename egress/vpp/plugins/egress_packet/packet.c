/* SPDX-License-Identifier: Apache-2.0 */
/* Connector Egress: pre-NAT PMTU with native ICMP generation. */
#include <egress_packet/packet.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vnet/gso/gso.h>
#include <vnet/interface_output.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_frag.h>
#include <vnet/ip/reass/ip4_full_reass.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>
#include <vpp/app/version.h>

/* AF_PACKET preserves kernel offload metadata. Normalize it before any
 * IPv4/Geneve/NAT processing, rather than requiring a borrowed peer or NIC to
 * disable its checksum/GSO features. Ordinary wire checksums stay untouched. */
enum
{
  NORMALIZE_DROP,
  NORMALIZE_N_NEXT
};
enum
{
  NORMALIZE_INVALID,
  NORMALIZE_NO_BUFFERS,
  NORMALIZE_SEGMENTED,
  NORMALIZE_CHECKSUMS,
  NORMALIZE_N_ERRORS
};
static char *normalize_errors[] = { "invalid offload metadata", "no segmentation buffers",
                                    "GSO packets segmented", "partial checksums completed" };
VLIB_NODE_FN (egress_normalize_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 retained[VLIB_FRAME_SIZE], count = 0;
  u16 nexts[VLIB_FRAME_SIZE];
  vnet_interface_per_thread_data_t *ptd
      = vec_elt_at_index (vnet_get_main ()->interface_main.per_thread_data, vm->thread_index);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 next;
      vnet_feature_next (&next, b);
      if (b->flags & VNET_BUFFER_F_GSO)
        {
          i32 l4 = vnet_buffer (b)->l4_hdr_offset - b->current_data;
          u32 header = l4 + vnet_buffer2 (b)->gso_l4_hdr_sz;
          u32 total = vlib_buffer_length_in_chain (vm, b);
          if (!(b->flags & VNET_BUFFER_F_IS_IP4)
              || !(vnet_buffer (b)->oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
              || !vnet_buffer2 (b)->gso_size || l4 < 20
              || vnet_buffer2 (b)->gso_l4_hdr_sz < sizeof (tcp_header_t)
              || header > b->current_length || header >= total)
            {
              b->error = node->errors[NORMALIZE_INVALID];
              next = NORMALIZE_DROP;
            }
          else
            {
              /* Native segmentation selects IPv4 fixup by this flag.
               * A kernel GSO packet may already have a valid aggregate IP
               * checksum, but every segment needs its own length/checksum. */
              vnet_buffer (b)->oflags |= VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
              vec_reset_length (ptd->split_buffers);
              if (gso_segment_buffer_inline (vm, ptd, b, 1))
                {
                  vlib_buffer_enqueue_to_single_next (vm, node, ptd->split_buffers, next,
                                                      vec_len (ptd->split_buffers));
                  vec_reset_length (ptd->split_buffers);
                  vlib_node_increment_counter (vm, node->node_index, NORMALIZE_SEGMENTED, 1);
                  vlib_buffer_free_one (vm, from[i]);
                  continue;
                }
              vec_reset_length (ptd->split_buffers);
              b->error = node->errors[NORMALIZE_NO_BUFFERS];
              next = NORMALIZE_DROP;
            }
        }
      else if (b->flags & VNET_BUFFER_F_OFFLOAD)
        {
          vnet_calc_checksums_inline (vm, b, !!(b->flags & VNET_BUFFER_F_IS_IP4),
                                      !!(b->flags & VNET_BUFFER_F_IS_IP6));
          vlib_node_increment_counter (vm, node->node_index, NORMALIZE_CHECKSUMS, 1);
        }
      retained[count] = from[i];
      nexts[count++] = next;
    }
  vlib_buffer_enqueue_to_next (vm, node, retained, nexts, count);
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (egress_normalize_node) = {
  .name = "egress-input-normalize",
  .vector_size = sizeof (u32),
  .n_errors = NORMALIZE_N_ERRORS,
  .error_strings = normalize_errors,
  .n_next_nodes = NORMALIZE_N_NEXT,
  .next_nodes = { [NORMALIZE_DROP] = "error-drop" },
};
VNET_FEATURE_INIT (egress_normalize_feature, static) = {
  .arc_name = "device-input",
  .node_name = "egress-input-normalize",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
static clib_error_t *
normalize_config (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  u32 sw;
  if (!unformat (in, "%U", unformat_vnet_sw_interface, vnet_get_main (), &sw)
      || unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected admitted interface");
  int rv = vnet_feature_enable_disable ("device-input", "egress-input-normalize", sw, 1, 0, 0);
  return rv ? clib_error_return (0, "input normalization failed: %d", rv) : 0;
}
VLIB_CLI_COMMAND (normalize_command, static) = {
  .path = "egress-packet-normalize",
  .short_help = "Internal offload normalization",
  .function = normalize_config,
};

static u32 *mtu_by_rx;

enum
{
  GUARD_NEXT_DROP,
  GUARD_NEXT_ICMP,
  GUARD_N_NEXT
};
enum
{
  GUARD_ERROR_ICMP,
  GUARD_N_ERROR
};
static char *guard_errors[] = { "pre-NAT DF packets sent to native ICMP" };

VLIB_NODE_FN (egress_packet_node) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u16 nexts[VLIB_FRAME_SIZE];
  u32 errors = 0;
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 next;
      vnet_feature_next (&next, b);
      u32 rx = vnet_buffer (b)->sw_if_index[VLIB_RX];
      u32 mtu = rx < vec_len (mtu_by_rx) ? mtu_by_rx[rx] : 0;
      ip4_header_t *ip = vlib_buffer_get_current (b);
      if (mtu && clib_net_to_host_u16 (ip->length) > mtu
          && (clib_net_to_host_u16 (ip->flags_and_fragment_offset) & 0x4000))
        {
          /* RX continues to identify the original attachment FIB. */
          vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
          icmp4_error_set_vnet_buffer (
              b, ICMP4_destination_unreachable,
              ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set, mtu);
          next = GUARD_NEXT_ICMP;
          errors++;
        }
      nexts[i] = next;
    }
  vlib_node_increment_counter (vm, node->node_index, GUARD_ERROR_ICMP, errors);
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (egress_packet_node) = {
  .name = "egress-packet-guard",
  .vector_size = sizeof (u32),
  .n_errors = GUARD_N_ERROR,
  .error_strings = guard_errors,
  .n_next_nodes = GUARD_N_NEXT,
  .next_nodes = {
    [GUARD_NEXT_DROP] = "error-drop",
    [GUARD_NEXT_ICMP] = "ip4-icmp-error",
  },
};

VNET_FEATURE_INIT (egress_packet_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "egress-packet-guard",
  .runs_after = VNET_FEATURES ("ip4-full-reassembly-feature"),
  .runs_before = VNET_FEATURES ("nat-pre-in2out", "nat44-in2out-worker-handoff", "nat44-ed-in2out"),
};

static clib_error_t *
guard_config (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 rx = ~0, mtu = 0;
  vnet_main_t *vnm = vnet_get_main ();
  if (!unformat (input, "%U mtu %u", unformat_vnet_sw_interface, vnm, &rx, &mtu) || mtu < 68
      || mtu > 65535)
    return clib_error_return (0, "expected interface mtu 68..65535");
  vec_validate (mtu_by_rx, rx);
  mtu_by_rx[rx] = mtu;
  int rv = vnet_feature_enable_disable ("ip4-unicast", "egress-packet-guard", rx, 1, 0, 0);
  if (rv)
    return clib_error_return (0, "feature enable failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (egress_packet_cli, static) = {
  .path = "egress-packet-guard",
  .short_help = "egress-packet-guard <interface> mtu <bytes>",
  .function = guard_config,
};

/* Egress: use the native shared fragment ID allocator for every
 * complete non-atomic packet, including packets fitting the local MTU. */
static u32 *id_mtu_by_rx;

/* Called under the main-thread worker barrier, before attachment publication. */
__clib_export int
egress_packet_bind (u32 sw, u8 enable)
{
  vec_validate (id_mtu_by_rx, sw);
  id_mtu_by_rx[sw] = enable ? 65535 : 0;
  return vnet_feature_enable_disable ("ip4-unicast", "egress-packet-id", sw, enable, 0, 0);
}

VLIB_NODE_FN (egress_packet_id_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u16 nexts[VLIB_FRAME_SIZE];
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 next;
      vnet_feature_next (&next, b);
      u32 rx = vnet_buffer (b)->sw_if_index[VLIB_RX];
      u32 mtu = rx < vec_len (id_mtu_by_rx) ? id_mtu_by_rx[rx] : 0;
      ip4_header_t *ip = vlib_buffer_get_current (b);
      if (mtu && !(clib_net_to_host_u16 (ip->flags_and_fragment_offset) & 0x4000))
        {
          ip_frag_set_vnet_buffer (b, mtu, IP_FRAG_NEXT_IP4_LOOKUP, 0);
          next = 0;
        }
      nexts[i] = next;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (egress_packet_id_node) = {
  .name = "egress-packet-id",
  .vector_size = sizeof (u32),
  .n_next_nodes = 1,
  .next_nodes = { [0] = "ip4-frag" },
};

VNET_FEATURE_INIT (egress_packet_id_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "egress-packet-id",
  .runs_after = VNET_FEATURES ("nat-pre-in2out", "nat44-in2out-worker-handoff", "nat44-ed-in2out",
                               "nat-pre-out2in", "nat44-out2in-worker-handoff", "nat44-ed-out2in"),
};

static clib_error_t *
id_config (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 rx = ~0, mtu = 0;
  vnet_main_t *vnm = vnet_get_main ();
  if (!unformat (input, "%U mtu %u", unformat_vnet_sw_interface, vnm, &rx, &mtu) || mtu < 68
      || mtu > 65535)
    return clib_error_return (0, "expected interface mtu 68..65535");
  vec_validate (id_mtu_by_rx, rx);
  id_mtu_by_rx[rx] = mtu;
  int rv = vnet_feature_enable_disable ("ip4-unicast", "egress-packet-id", rx, 1, 0, 0);
  return rv ? clib_error_return (0, "feature enable failed: %d", rv) : 0;
}

VLIB_CLI_COMMAND (egress_packet_id_cli, static) = {
  .path = "egress-packet-id",
  .short_help = "egress-packet-id <interface> mtu <bytes>",
  .function = id_config,
};

static clib_error_t *
reass_config (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  /* Outstanding fragment sets are bounded by the actual packet buffers,
   * not by an unrelated fixed object count. A valid IPv4 datagram can use
   * eight-byte fragments up to its 16-bit wire length. */
  u64 available = 0;
  vlib_buffer_pool_t *pool;
  vec_foreach (pool, vm->buffer_main->buffer_pools) available += pool->n_buffers;
  if (!available)
    return clib_error_return (0, "no native packet buffers");
  int rv = ip4_full_reass_set (200, clib_min (available, (u64)~0U), 8192, 50);
  return rv ? clib_error_return (0, "native full reassembly configuration: %d", rv) : 0;
}

VLIB_CLI_COMMAND (egress_packet_reass_cli, static) = {
  .path = "egress-packet-reassembly",
  .short_help = "egress-packet-reassembly (native timeout200ms, count1024, length128, walk50ms)",
  .function = reass_config,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Connector Egress packet normalization",
};
