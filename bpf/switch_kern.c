// SPDX-License-Identifier: GPL-2.0-only
// sandbox-switch eBPF TC programs
//
// TC program attachment points:
// - tc_ingress_nx: ingress on sw-nX (sandbox port peer) - handles outgoing sandbox traffic
// - tc_ingress_mx: ingress on sw-mX (mgmt port peer) - ARP proxy
// - tc_ingress_transit: ingress on transit_dev - handles GENEVE decapsulation

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "common.h"
#include "stats.h"


// Map definitions
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PORTS);
    __uint(map_flags, BPF_F_MMAPABLE);  // Enable mmap for userspace CAS
    __type(key, __u32);
    __type(value, struct slot_item);
} slots SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct switch_config);
} config SEC(".maps");

// Userspace-only metadata (eBPF programs do not access this)
// Stored as JSON bytes for flexible schema evolution.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __uint(value_size, METADATA_MAX_SIZE);
} metadata SEC(".maps");



// Reverse lookup: ifindex -> slot_id (for sw-nX devices)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u32);
    __type(value, __u32);
} ifindex_to_slot SEC(".maps");

// Per-slot opaque GENEVE options. slot_item.geneve_opts_len is the hot-path
// hint: len==0 avoids this map lookup for legacy traffic.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u32);
    __type(value, struct geneve_opts_value);
} geneve_opts SEC(".maps");

// Management service NAT (switch-global, see struct svc_key/svc_val in common.h).
// fwd: egress {VIP,vport,proto} -> {target_ip,target_port} (tc_ingress_nx)
// rev: ingress {target_ip,tport,proto} -> {VIP,vport}      (tc_ingress_mx)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MGMT_SVC);
    __type(key, struct svc_key);
    __type(value, struct svc_val);
} mgmt_svc_fwd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MGMT_SVC);
    __type(key, struct svc_key);
    __type(value, struct svc_val);
} mgmt_svc_rev SEC(".maps");

// Helper: check if MAC is all zeros
static __always_inline int is_zero_mac(const __u8 *mac) {
    return (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) == 0;
}

// Helper: get port MAC address
// If port_mac is all zeros (per-port mode): derive from switch_mac with slot_id
// If port_mac is non-zero (fixed mode): use the fixed port_mac value
static __always_inline void get_port_mac(__u8 *mac,
    const struct switch_config *cfg, __u32 slot_id)
{
    if (is_zero_mac(cfg->port_mac)) {
        // per-port: copy first 4 bytes from switch_mac
        // byte4 = ((switch_mac[4] ^ 0x80) & 0x80) | (slot_id >> 8)
        // byte5 = slot_id & 0xFF
        __bpf_memcpy(mac, cfg->switch_mac, 4);
        mac[4] = ((cfg->switch_mac[4] ^ PORT_MAC_XOR) & PORT_MAC_XOR) | ((__u8)(slot_id >> 8));
        mac[5] = (__u8)(slot_id & 0xff);
    } else {
        // fixed/custom: use port_mac
        __bpf_memcpy(mac, cfg->port_mac, 6);
    }
}

// Helper: compute IP checksum
static __always_inline __u16 csum_fold(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u32 csum_add(__u32 csum, __u32 addend)
{
    csum += addend;
    return csum + (csum < addend);
}

static __always_inline __u16 ip_checksum(void *data, int len)
{
    __u32 sum = 0;
    __u16 *p = data;

    #pragma unroll
    for (int i = 0; i < 10; i++) { // IP header is 20 bytes = 10 shorts
        if (i * 2 >= len)
            break;
        sum = csum_add(sum, p[i]);
    }
    return csum_fold(sum);
}

// Helper: send ARP reply with a specified reply MAC
static __always_inline int send_arp_reply_with_mac(struct __sk_buff *skb,
                                                    __u8 reply_mac[6],
                                                    void *data, void *data_end)
{
    struct ethhdr *eth = data;
    struct arphdr *arp = (void *)(eth + 1);
    struct arp_eth_payload *arp_data;

    if ((void *)(arp + 1) > data_end)
        return TC_ACT_OK;

    // Only handle ARP requests for IPv4 over Ethernet
    if (bpf_ntohs(arp->ar_hrd) != 1 ||  // Ethernet
        bpf_ntohs(arp->ar_pro) != ETH_P_IP ||
        arp->ar_hln != ETH_ALEN ||
        arp->ar_pln != 4 ||
        bpf_ntohs(arp->ar_op) != ARPOP_REQUEST)
        return TC_ACT_OK;

    arp_data = (void *)(arp + 1);
    if ((void *)(arp_data + 1) > data_end)
        return TC_ACT_OK;

    // Save original values
    __be32 orig_sip = arp_data->ar_sip;
    __be32 orig_tip = arp_data->ar_tip;
    unsigned char orig_sha[6];
    __bpf_memcpy(orig_sha, arp_data->ar_sha, 6);

    // Build ARP reply
    // Set destination MAC to original sender
    __bpf_memcpy(eth->h_dest, orig_sha, 6);
    // Set source MAC to reply MAC
    __bpf_memcpy(eth->h_source, reply_mac, 6);

    // Set ARP opcode to reply
    arp->ar_op = bpf_htons(ARPOP_REPLY);

    // Sender = reply MAC (with target IP)
    __bpf_memcpy(arp_data->ar_sha, reply_mac, 6);
    arp_data->ar_sip = orig_tip;

    // Target = original sender
    __bpf_memcpy(arp_data->ar_tha, orig_sha, 6);
    arp_data->ar_tip = orig_sip;

    // Send back on same interface
    return bpf_redirect(skb->ingress_ifindex, 0);
}

// Helper: check if destination IP matches any mgmt CIDR
// Optimized layout: check inline mgmt_cidrs_0 first (hot path, Cache Line 0),
// then check mgmt_cidrs_ext array (cold path, Cache Line 1)
static __always_inline int match_mgmt_cidr(struct slot_item *slot, __be32 dst_ip,
                                            __u32 *out_ifindex, __u8 out_mac[6])
{
    // Check inline mgmt_cidrs_0 first (hot path, in Cache Line 0)
    if (slot->mgmt_cidr_count > 0) {
        struct mgmt_cidr *cidr = &slot->mgmt_cidrs_0;
        if ((bpf_ntohl(dst_ip) & cidr->mask) == (cidr->ip & cidr->mask)) {
            *out_ifindex = cidr->ifindex;
            __bpf_memcpy(out_mac, cidr->mgmt_mac, 6);
            return 1;
        }
    }

    // Check extended array (cold path, in Cache Line 1)
    // Manually unrolled since MAX_MGMT_CIDR_EXT = 2
    if (slot->mgmt_cidr_count > 1) {
        struct mgmt_cidr *cidr = &slot->mgmt_cidrs_ext[0];
        if ((bpf_ntohl(dst_ip) & cidr->mask) == (cidr->ip & cidr->mask)) {
            *out_ifindex = cidr->ifindex;
            __bpf_memcpy(out_mac, cidr->mgmt_mac, 6);
            return 1;
        }
    }
    if (slot->mgmt_cidr_count > 2) {
        struct mgmt_cidr *cidr = &slot->mgmt_cidrs_ext[1];
        if ((bpf_ntohl(dst_ip) & cidr->mask) == (cidr->ip & cidr->mask)) {
            *out_ifindex = cidr->ifindex;
            __bpf_memcpy(out_mac, cidr->mgmt_mac, 6);
            return 1;
        }
    }
    return 0;
}

// TC ingress on sw-nX: handle sandbox outgoing traffic
// - ARP proxy reply
// - Management plane traffic: SNAT and redirect to sw-mX
// - External traffic: GENEVE encapsulation
SEC("tc/ingress_nx")
int tc_ingress_nx(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Get config
    __u32 cfg_key = 0;
    struct switch_config *cfg = bpf_map_lookup_elem(&config, &cfg_key);
    if (!cfg)
        return TC_ACT_OK;

    // Cache config values
    __u8 switch_mac[6];
    __bpf_memcpy(switch_mac, cfg->switch_mac, 6);
    __u32 floating_ip_base = cfg->floating_ip_base;
    __u32 geneve_port_base = cfg->geneve_port_base;
    __u8  geneve_encap_eth = cfg->geneve_encap_eth;
    __u8  geneve_locator = cfg->geneve_locator;
    __u8  geneve_tlv_type = cfg->geneve_tlv_type;
    __u16 geneve_tlv_class = cfg->geneve_tlv_class;

    // Get slot_id from ifindex
    __u32 ifindex = skb->ingress_ifindex;
    __u32 *slot_id_ptr = bpf_map_lookup_elem(&ifindex_to_slot, &ifindex);
    if (!slot_id_ptr)
        return TC_ACT_OK;
    __u32 slot_id = *slot_id_ptr;

    // Get slot config
    struct slot_item *slot = bpf_map_lookup_elem(&slots, &slot_id);
    __u64 generation = stats_generation(slot_id);
    if (!slot || is_slot_free(slot->inner_ip))
        return TC_ACT_OK;

    // Cache slot values
    __u32 transit_ifindex = slot->transit_ifindex;
    __u32 transit_ip = slot->transit_ip;
    __u32 transit_gateway_ip = slot->transit_gateway_ip;
    __u32 transit_geneve_vni = slot->transit_geneve_vni;
    __u8 geneve_opts_len = slot->geneve_opts_len;

    __be16 proto = eth->h_proto;

    // Cache transit_mac before any skb modifications (needed for GENEVE encap)
    __u8 transit_mac[6];
    __bpf_memcpy(transit_mac, slot->transit_mac, 6);

    // Handle ARP: dispatch based on target IP
    if (proto == bpf_htons(ETH_P_ARP)) {
        // Parse ARP to get target IP
        struct arphdr *arp_hdr = (void *)(eth + 1);
        if ((void *)(arp_hdr + 1) > data_end)
            return TC_ACT_OK;
        struct arp_eth_payload *arp_pl = (void *)(arp_hdr + 1);
        if ((void *)(arp_pl + 1) > data_end)
            return TC_ACT_OK;

        __be32 arp_tip = arp_pl->ar_tip;
        // Check if ARP target matches a mgmt CIDR
        __u32 _arp_ifindex = 0;
        __u8 arp_reply_mac[6];
        if (match_mgmt_cidr(slot, arp_tip, &_arp_ifindex, arp_reply_mac)) {
            return send_arp_reply_with_mac(skb, arp_reply_mac, data, data_end);
        }
        // Non-mgmt ARP: reply with switch_mac
        return send_arp_reply_with_mac(skb, switch_mac, data, data_end);
    }

    // Handle IPv4-specific: management CIDR check
    __u32 pkt_len = skb->len;
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        __be32 dst_ip = ip->daddr;

        // Check if destination matches management CIDR
        __u32 mgmt_ifindex = 0;
        __u8 mgmt_dev_mac[6];
        if (match_mgmt_cidr(slot, dst_ip, &mgmt_ifindex, mgmt_dev_mac)) {
            // Management plane traffic: SNAT src IP to floating IP
            __be32 floating_ip = bpf_htonl(floating_ip_base + slot_id);
            __be32 old_sip = ip->saddr;
            __u8 protocol = ip->protocol;
            __u8 ihl = ip->ihl;

            // Service NAT lookup (egress): VIP:vport -> target_ip:target_port.
            // Read the L4 dest port and resolve the target BEFORE any
            // skb_store_bytes (which can invalidate data pointers); all rewrites
            // below use fixed offsets so they stay valid afterwards.
            int    svc_hit = 0;
            __be32 svc_new_dip = 0;
            __be16 svc_old_dport = 0, svc_new_dport = 0;
            if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
                __be16 *l4 = (void *)((char *)ip + (ihl * 4));
                if ((void *)(l4 + 2) <= data_end) {
                    // Map keys/values are host byte order (same convention as
                    // mgmt_cidr); convert at the packet boundary.
                    struct svc_key k = {};
                    k.ip = bpf_ntohl(dst_ip);   // original VIP (host order)
                    k.port = bpf_ntohs(l4[1]);  // dest port (host order)
                    k.proto = protocol;
                    struct svc_val *v = bpf_map_lookup_elem(&mgmt_svc_fwd, &k);
                    if (v) {
                        svc_hit = 1;
                        svc_old_dport = l4[1];           // network order (for csum/store)
                        svc_new_dip = bpf_htonl(v->ip);  // back to network order
                        svc_new_dport = bpf_htons(v->port);
                    }
                }
            }

            // Update source IP using skb_store_bytes
            bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, saddr),
                                &floating_ip, sizeof(floating_ip), 0);

            // Update IP checksum (incremental)
            bpf_l3_csum_replace(skb,
                sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                old_sip, floating_ip, sizeof(__be32));

            // For UDP, also update L4 checksum
            if (protocol == IPPROTO_UDP) {
                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                struct udphdr *udp = data + sizeof(struct ethhdr) + (ihl * 4);
                if ((void *)(udp + 1) <= data_end && udp->check != 0) {
                    bpf_l4_csum_replace(skb,
                        sizeof(struct ethhdr) + (ihl * 4) + offsetof(struct udphdr, check),
                        old_sip, floating_ip, BPF_F_PSEUDO_HDR | sizeof(__be32));
                }
            } else if (protocol == IPPROTO_TCP) {
                bpf_l4_csum_replace(skb,
                    sizeof(struct ethhdr) + (ihl * 4) + 16,
                    old_sip, floating_ip, BPF_F_PSEUDO_HDR | sizeof(__be32));
            }

            // Apply service DNAT: dst IP (+ dst port) -> target. The pseudo-header
            // L4 checksum covers the dst-IP change; the port delta is folded in
            // separately. Port write is unconditional on the checksum (UDP may
            // carry check==0 = no checksum).
            if (svc_hit) {
                __be32 old_dip = dst_ip;
                int port_changed = (svc_new_dport != svc_old_dport);

                bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr),
                                    &svc_new_dip, sizeof(svc_new_dip), 0);
                bpf_l3_csum_replace(skb,
                    sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                    old_dip, svc_new_dip, sizeof(__be32));

                if (protocol == IPPROTO_UDP) {
                    data = (void *)(long)skb->data;
                    data_end = (void *)(long)skb->data_end;
                    struct udphdr *udp = data + sizeof(struct ethhdr) + (ihl * 4);
                    if ((void *)(udp + 1) <= data_end && udp->check != 0) {
                        __u32 coff = sizeof(struct ethhdr) + (ihl * 4) + offsetof(struct udphdr, check);
                        bpf_l4_csum_replace(skb, coff, old_dip, svc_new_dip, BPF_F_PSEUDO_HDR | sizeof(__be32));
                        if (port_changed)
                            bpf_l4_csum_replace(skb, coff, svc_old_dport, svc_new_dport, sizeof(__be16));
                    }
                } else { // TCP
                    __u32 coff = sizeof(struct ethhdr) + (ihl * 4) + 16;
                    bpf_l4_csum_replace(skb, coff, old_dip, svc_new_dip, BPF_F_PSEUDO_HDR | sizeof(__be32));
                    if (port_changed)
                        bpf_l4_csum_replace(skb, coff, svc_old_dport, svc_new_dport, sizeof(__be16));
                }

                if (port_changed)
                    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + (ihl * 4) + 2,
                                        &svc_new_dport, sizeof(svc_new_dport), 0);
            }

            // Re-fetch data pointers and update MAC addresses
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end)
                return TC_ACT_OK;

            __bpf_memcpy(eth->h_dest, mgmt_dev_mac, 6);
            __bpf_memcpy(eth->h_source, switch_mac, 6);

            update_stats_mgmt_tx(slot_id, generation, pkt_len);
            return bpf_redirect(mgmt_ifindex, 0);
        }
    }

    // Only handle IPv4 and IPv6 for transit encapsulation
    if (proto != bpf_htons(ETH_P_IP) && proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;

    // External traffic: GENEVE encapsulation
    if (transit_ifindex == 0 || transit_gateway_ip == 0)
        return TC_ACT_OK;  // No transit configured

    // Select the configured slot locator and derive the wire port/VNI.
    __u16 geneve_port = 0;
    __u32 wire_geneve_vni = 0;
    __u32 locator_len = 0;
    switch (geneve_locator) {
    case GENEVE_LOCATOR_PORT:
        geneve_port = geneve_port_base + slot_id;
        wire_geneve_vni = transit_geneve_vni;
        break;
    case GENEVE_LOCATOR_VNI:
        geneve_port = GENEVE_PORT;
        wire_geneve_vni = (slot_id << GENEVE_VNI_LOCATOR_BITS) |
                          transit_geneve_vni;
        break;
    case GENEVE_LOCATOR_TLV:
        geneve_port = GENEVE_PORT;
        wire_geneve_vni = transit_geneve_vni;
        locator_len = GENEVE_TLV_LOCATOR_LEN;
        break;
    default:
        return TC_ACT_OK;
    }

    // Validate the fast-path hint before using it. A non-zero hint requires a
    // matching full value; mismatches fail closed instead of sending partial
    // options or reading beyond the fixed map value.
    struct geneve_opts_value *user_opts = 0;
    __u32 user_opts_words[MAX_GENEVE_OPTS_LEN / 4] = {};
    __u8 user_opts_critical = 0;
    if (geneve_opts_len > 0) {
        if (geneve_opts_len > MAX_GENEVE_OPTS_LEN ||
            (geneve_opts_len & 3) != 0)
            return TC_ACT_OK;
        user_opts = bpf_map_lookup_elem(&geneve_opts, &slot_id);
        if (!user_opts || user_opts->len != geneve_opts_len ||
            user_opts->len > MAX_GENEVE_OPTS_LEN ||
            (user_opts->len & 3) != 0 || user_opts->critical > 1)
            return TC_ACT_OK;
        user_opts_critical = user_opts->critical;

        // Map-value pointers cannot be carried across bpf_skb_adjust_room.
        // Snapshot the bounded fixed-size value first, then write the packet
        // only from verifier-tracked stack memory after the helper call.
#pragma unroll
        for (int i = 0; i < MAX_GENEVE_OPTS_LEN / 4; i++) {
            if ((__u32)(i * 4) >= geneve_opts_len)
                break;
            __bpf_memcpy(&user_opts_words[i], &user_opts->data[i * 4], 4);
        }
    }

    __u32 total_opts_len = locator_len + geneve_opts_len;
    if (total_opts_len > MAX_GENEVE_OPTS_LEN)
        return TC_ACT_OK;

    // Compute outer UDP source port from inner packet tuple hash.
    // This enables ECMP/RSS load balancing on the underlay network.
    __u32 hash_val = 0;
    if (proto == bpf_htons(ETH_P_IP)) {
        // Hash inner IPv4 5-tuple: src_ip, dst_ip, protocol, src_port, dst_port
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;
        hash_val = bpf_ntohl(ip->saddr) ^ bpf_ntohl(ip->daddr) ^ ip->protocol;
        if (ip->protocol == IPPROTO_UDP || ip->protocol == IPPROTO_TCP) {
            __u32 l4_off = sizeof(struct ethhdr) + (ip->ihl * 4);
            __be16 *l4_ports = data + l4_off;
            if ((void *)(l4_ports + 2) <= data_end)
                hash_val ^= ((__u32)bpf_ntohs(l4_ports[0]) << 16) | bpf_ntohs(l4_ports[1]);
        }
    } else {
        // Hash inner IPv6: partial src/dst addresses + next header
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;
        hash_val = ip6->saddr.u6_addr32[0] ^
                   ip6->saddr.u6_addr32[3] ^
                   ip6->daddr.u6_addr32[0] ^
                   ip6->daddr.u6_addr32[3] ^
                   ip6->nexthdr;
        if (ip6->nexthdr == IPPROTO_UDP || ip6->nexthdr == IPPROTO_TCP) {
            __u32 l4_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            __be16 *l4_ports = data + l4_off;
            if ((void *)(l4_ports + 2) <= data_end)
                hash_val ^= ((__u32)bpf_ntohs(l4_ports[0]) << 16) | bpf_ntohs(l4_ports[1]);
        }
    }
    // Mix bits (Jenkins one-at-a-time finalizer)
    hash_val += (hash_val << 3);
    hash_val ^= (hash_val >> 11);
    hash_val += (hash_val << 15);
    // Map to ephemeral port range 49152-65535 (16384 ports)
    __u16 src_port = 49152 + (hash_val & 0x3fff);

    // Encapsulation: outer IP + UDP + GENEVE headers.
    // For Ether-over-GENEVE, also include inner ETH in encap_len
    // so bpf_skb_adjust_room creates space for it.
    __u32 tunnel_len = sizeof(struct iphdr) + sizeof(struct udphdr) +
                       sizeof(struct genevehdr) + total_opts_len;
    __u32 encap_len = tunnel_len;
    __u64 adj_flags = BPF_F_ADJ_ROOM_ENCAP_L4_UDP | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4;
    if (geneve_encap_eth) {
        encap_len += sizeof(struct ethhdr);
        adj_flags |= BPF_F_ADJ_ROOM_ENCAP_L2(sizeof(struct ethhdr));
    }

    if (bpf_skb_adjust_room(skb, encap_len, BPF_ADJ_ROOM_MAC, adj_flags) < 0)
        return TC_ACT_OK;

    // Re-fetch data pointers after adjustment
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return TC_ACT_OK;

    struct udphdr *udp = (void *)(outer_ip + 1);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    struct genevehdr *geneve = (void *)(udp + 1);
    if ((void *)(geneve + 1) > data_end)
        return TC_ACT_OK;

    void *geneve_opts_start = (void *)(geneve + 1);
    if ((void *)((char *)geneve_opts_start + total_opts_len) > data_end)
        return TC_ACT_OK;

    // Fill outer Ethernet header
    __bpf_memcpy(eth->h_dest, switch_mac, 6);
    __bpf_memcpy(eth->h_source, switch_mac, 6);
    eth->h_proto = bpf_htons(ETH_P_IP);

    // For Ether-over-GENEVE: fill the inner Ethernet header after all options.
    if (geneve_encap_eth) {
        struct ethhdr *inner_eth = (void *)((char *)geneve_opts_start +
                                            total_opts_len);
        if ((void *)(inner_eth + 1) > data_end)
            return TC_ACT_OK;
        // Destination: transit_mac (broadcast if all-zero)
        __u8 inner_dst[6];
        __bpf_memcpy(inner_dst, transit_mac, 6);
        __u8 is_transit_mac_zero = 1;
        #pragma unroll
        for (int z = 0; z < 6; z++)
            if (inner_dst[z]) is_transit_mac_zero = 0;
        if (is_transit_mac_zero)
            __bpf_memset(inner_dst, 0xff, 6);
        __bpf_memcpy(inner_eth->h_dest, inner_dst, 6);
        // Source: port MAC (fixed or per-slot derived)
        get_port_mac(inner_eth->h_source, cfg, slot_id);
        inner_eth->h_proto = proto;  // preserve inner protocol (IPv4/IPv6)
    }

    // Fill outer IP header
    outer_ip->version = 4;
    outer_ip->ihl = 5;
    outer_ip->tos = 0;
    outer_ip->tot_len = bpf_htons(skb->len - sizeof(struct ethhdr));
    outer_ip->id = 0;
    outer_ip->frag_off = bpf_htons(0x4000);  // Don't fragment
    outer_ip->ttl = 64;
    outer_ip->protocol = IPPROTO_UDP;
    outer_ip->check = 0;
    outer_ip->saddr = bpf_htonl(transit_ip);
    outer_ip->daddr = bpf_htonl(transit_gateway_ip);
    outer_ip->check = ip_checksum(outer_ip, sizeof(struct iphdr));

    // Fill UDP header.
    // src: hash of inner tuple (for ECMP/RSS on underlay)
    // dst: selected by the configured locator; port mode uses a slot-specific
    // destination for receiver-side slot identification.
    udp->source = bpf_htons(src_port);
    udp->dest = bpf_htons(geneve_port);
    udp->len = bpf_htons(skb->len - sizeof(struct ethhdr) - sizeof(struct iphdr));
    udp->check = 0;  // Optional for IPv4

    // Fill GENEVE base flags as wire bytes. Avoid C bitfields here: their C
    // layout depends on userspace header macros which are not part of the BPF
    // target ABI. Version, OAM, and reserved bits are all zero.
    __u8 geneve_critical = user_opts_critical ||
                           (geneve_locator == GENEVE_LOCATOR_TLV &&
                            (geneve_tlv_type & 0x80));
    ((__u8 *)geneve)[0] = total_opts_len / 4;
    ((__u8 *)geneve)[1] = geneve_critical ? 0x40 : 0;
    geneve->proto_type = geneve_encap_eth ? bpf_htons(ETH_P_TEB) : proto;
    geneve->vni[0] = (wire_geneve_vni >> 16) & 0xff;
    geneve->vni[1] = (wire_geneve_vni >> 8) & 0xff;
    geneve->vni[2] = wire_geneve_vni & 0xff;
    geneve->rsvd2 = 0;

    // The generated locator is always first and exactly 8 bytes.
    void *opaque_opts_start = geneve_opts_start;
    if (geneve_locator == GENEVE_LOCATOR_TLV) {
        struct geneve_opt_hdr *locator = geneve_opts_start;
        if ((void *)(locator + 1) > data_end ||
            (void *)((char *)locator + GENEVE_TLV_LOCATOR_LEN) > data_end)
            return TC_ACT_OK;
        locator->opt_class = bpf_htons(geneve_tlv_class);
        locator->type = geneve_tlv_type;
        locator->rsvd_len = 1;
        __be32 locator_data = bpf_htonl(slot_id);
        __bpf_memcpy((void *)(locator + 1), &locator_data,
                     sizeof(locator_data));
        opaque_opts_start = (void *)((char *)geneve_opts_start +
                                     GENEVE_TLV_LOCATOR_LEN);
    }

    // Copy at most 16 fixed words. The loop is fully unrolled so the verifier
    // sees constant map-value offsets and a hard 64-byte packet bound.
    if (geneve_opts_len > 0) {
#pragma unroll
        for (int i = 0; i < MAX_GENEVE_OPTS_LEN / 4; i++) {
            if ((__u32)(i * 4) >= geneve_opts_len)
                break;
            void *dst = (void *)((char *)opaque_opts_start + i * 4);
            if ((void *)((char *)dst + 4) > data_end)
                return TC_ACT_OK;
            __bpf_memcpy(dst, &user_opts_words[i], 4);
        }
    }

    update_stats_transit_tx(slot_id, generation, pkt_len);

    // Use bpf_redirect_neigh to handle L2 neighbor resolution automatically.
    // If transit_nexthop is set, provide explicit nexthop to avoid FIB lookup
    // failure when the GENEVE destination is not on the same subnet as transit-dev.
    __u32 nexthop = cfg->transit_nexthop;
    if (nexthop) {
        struct bpf_redir_neigh nh = {};
        nh.nh_family = AF_INET;
        nh.ipv4_nh = bpf_htonl(nexthop);
        return bpf_redirect_neigh(transit_ifindex, &nh, sizeof(nh), 0);
    }
    return bpf_redirect_neigh(transit_ifindex, 0, 0, 0);
}

// TC ingress on sw-mX: ARP proxy + management response DNAT
// Handles both ARP requests (proxy reply) and IP packets from mgmt service
// (DNAT floating_ip -> inner_ip, redirect to sw-nX)
SEC("tc/ingress_mx")
int tc_ingress_mx(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Get config
    __u32 cfg_key = 0;
    struct switch_config *cfg = bpf_map_lookup_elem(&config, &cfg_key);
    if (!cfg)
        return TC_ACT_OK;

    // Cache config values
    __u8 switch_mac[6];
    __bpf_memcpy(switch_mac, cfg->switch_mac, 6);
    __u32 floating_ip_base = cfg->floating_ip_base;
    __u32 n_ports = cfg->n_ports;

    // Handle ARP: derive reply MAC based on target IP
    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        struct arphdr *arp_hdr = (void *)(eth + 1);
        if ((void *)(arp_hdr + 1) > data_end)
            return TC_ACT_OK;
        struct arp_eth_payload *arp_pl = (void *)(arp_hdr + 1);
        if ((void *)(arp_pl + 1) > data_end)
            return TC_ACT_OK;

        __u32 tip_host = bpf_ntohl(arp_pl->ar_tip);
        __u8 reply_mac[6];
        if (tip_host >= floating_ip_base && (tip_host - floating_ip_base) < n_ports) {
            // Use port MAC (fixed or per-slot derived)
            __u32 sid = tip_host - floating_ip_base;
            get_port_mac(reply_mac, cfg, sid);
        } else {
            // Non-port ARP: reply with switch_mac
            __bpf_memcpy(reply_mac, switch_mac, 6);
        }
        return send_arp_reply_with_mac(skb, reply_mac, data, data_end);
    }

    // Handle IP: DNAT floating_ip -> inner_ip and redirect to sw-nX
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Calculate slot_id from destination IP (floating IP)
    __u32 dst_ip_host = bpf_ntohl(ip->daddr);
    if (dst_ip_host < floating_ip_base)
        return TC_ACT_OK;

    __u32 slot_id = dst_ip_host - floating_ip_base;
    if (slot_id >= n_ports)
        return TC_ACT_OK;

    // Get slot config
    struct slot_item *slot = bpf_map_lookup_elem(&slots, &slot_id);
    __u64 generation = stats_generation(slot_id);
    if (!slot || is_slot_free(slot->inner_ip) || slot->ifindex == 0)
        return TC_ACT_OK;

    // Cache slot values
    __u32 inner_ip = slot->inner_ip;
    __u32 target_ifindex = slot->ifindex;

    // DNAT: replace floating_ip with inner_ip
    __be32 old_dip = ip->daddr;
    __be32 new_dip = bpf_htonl(inner_ip);
    __u8 protocol = ip->protocol;
    __u8 ihl = ip->ihl;

    // Service NAT reverse lookup (ingress): target_ip:tport -> VIP:vport.
    // Resolve BEFORE any skb_store_bytes; rewrites below use fixed offsets.
    int    svc_hit = 0;
    __be32 svc_old_sip = 0, svc_new_sip = 0;
    __be16 svc_old_sport = 0, svc_new_sport = 0;
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        __be16 *l4 = (void *)((char *)ip + (ihl * 4));
        if ((void *)(l4 + 2) <= data_end) {
            // Map keys/values are host byte order; convert at the packet boundary.
            struct svc_key k = {};
            k.ip = bpf_ntohl(ip->saddr);  // reply source = target_ip (host order)
            k.port = bpf_ntohs(l4[0]);    // source port (host order)
            k.proto = protocol;
            struct svc_val *v = bpf_map_lookup_elem(&mgmt_svc_rev, &k);
            if (v) {
                svc_hit = 1;
                svc_old_sip = ip->saddr;          // network order (for csum)
                svc_old_sport = l4[0];            // network order (for csum/store)
                svc_new_sip = bpf_htonl(v->ip);   // back to network order
                svc_new_sport = bpf_htons(v->port);
            }
        }
    }

    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr),
                        &new_dip, sizeof(new_dip), 0);

    bpf_l3_csum_replace(skb,
        sizeof(struct ethhdr) + offsetof(struct iphdr, check),
        old_dip, new_dip, sizeof(__be32));

    // Update L4 checksum for UDP
    if (protocol == IPPROTO_UDP) {
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        struct udphdr *udp = data + sizeof(struct ethhdr) + (ihl * 4);
        if ((void *)(udp + 1) <= data_end && udp->check != 0) {
            bpf_l4_csum_replace(skb,
                sizeof(struct ethhdr) + (ihl * 4) + offsetof(struct udphdr, check),
                old_dip, new_dip, BPF_F_PSEUDO_HDR | sizeof(__be32));
        }
    } else if (protocol == IPPROTO_TCP) {
        bpf_l4_csum_replace(skb,
            sizeof(struct ethhdr) + (ihl * 4) + 16,
            old_dip, new_dip, BPF_F_PSEUDO_HDR | sizeof(__be32));
    }

    // Apply service reverse SNAT: src IP (+ src port) target -> VIP, so the
    // sandbox sees the reply coming from the VIP it addressed.
    if (svc_hit) {
        int port_changed = (svc_new_sport != svc_old_sport);

        bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, saddr),
                            &svc_new_sip, sizeof(svc_new_sip), 0);
        bpf_l3_csum_replace(skb,
            sizeof(struct ethhdr) + offsetof(struct iphdr, check),
            svc_old_sip, svc_new_sip, sizeof(__be32));

        if (protocol == IPPROTO_UDP) {
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            struct udphdr *udp = data + sizeof(struct ethhdr) + (ihl * 4);
            if ((void *)(udp + 1) <= data_end && udp->check != 0) {
                __u32 coff = sizeof(struct ethhdr) + (ihl * 4) + offsetof(struct udphdr, check);
                bpf_l4_csum_replace(skb, coff, svc_old_sip, svc_new_sip, BPF_F_PSEUDO_HDR | sizeof(__be32));
                if (port_changed)
                    bpf_l4_csum_replace(skb, coff, svc_old_sport, svc_new_sport, sizeof(__be16));
            }
        } else { // TCP
            __u32 coff = sizeof(struct ethhdr) + (ihl * 4) + 16;
            bpf_l4_csum_replace(skb, coff, svc_old_sip, svc_new_sip, BPF_F_PSEUDO_HDR | sizeof(__be32));
            if (port_changed)
                bpf_l4_csum_replace(skb, coff, svc_old_sport, svc_new_sport, sizeof(__be16));
        }

        if (port_changed)
            bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + (ihl * 4) + 0,
                                &svc_new_sport, sizeof(svc_new_sport), 0);
    }

    // Update MAC addresses: dst = port MAC (fixed or per-slot derived), src = switch_mac
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Destination: port MAC (fixed or per-slot derived)
    get_port_mac(eth->h_dest, cfg, slot_id);
    __bpf_memcpy(eth->h_source, switch_mac, 6);

    __u32 pkt_len = skb->len;
    update_stats_mgmt_rx(slot_id, generation, pkt_len);

    return bpf_redirect(target_ifindex, 0);
}

// TC ingress on transit_dev: GENEVE decapsulation
SEC("tc/ingress_transit")
int tc_ingress_transit(struct __sk_buff *skb)
{
    // Linearize enough data for all headers we need to parse:
    // ETH(14) + IP(20) + UDP(8) + GENEVE(8) + inner ETH(14) = 64 bytes minimum.
    // Use skb->len to pull everything if packet is small, otherwise pull 64.
    __u32 pull_len = skb->len < 128 ? skb->len : 128;
    if (bpf_skb_pull_data(skb, pull_len) < 0)
        return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->ihl != 5)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    // Get config and cache values
    __u32 cfg_key = 0;
    struct switch_config *cfg = bpf_map_lookup_elem(&config, &cfg_key);
    if (!cfg)
        return TC_ACT_OK;

    __u8 switch_mac[6];
    __bpf_memcpy(switch_mac, cfg->switch_mac, 6);
    __u32 geneve_port_base = cfg->geneve_port_base;
    __u32 n_ports = cfg->n_ports;

    struct genevehdr *geneve = (void *)(udp + 1);
    if ((void *)(geneve + 1) > data_end)
        return TC_ACT_OK;

    // Parse the RFC wire bits directly rather than relying on target-specific
    // C bitfield layout.
    __u8 geneve_flags0 = ((__u8 *)geneve)[0];
    __u8 geneve_flags1 = ((__u8 *)geneve)[1];
    if ((geneve_flags0 >> 6) != 0)
        return TC_ACT_OK;

    __u32 geneve_opt_len = (geneve_flags0 & 0x3f) * 4;
    __u8 geneve_critical = !!(geneve_flags1 & 0x40);
    if (geneve_opt_len > MAX_GENEVE_OPTS_LEN)
        return TC_ACT_OK;

    __u16 dst_port = bpf_ntohs(udp->dest);
    __u32 wire_vni = (((__u32)geneve->vni[0]) << 16) |
                     (((__u32)geneve->vni[1]) << 8) |
                     ((__u32)geneve->vni[2]);
    __u32 slot_id = 0;
    __u32 received_vni = 0;

    // Return traffic has a deliberately strict framing contract. port/vni
    // accept no options; tlv accepts exactly the generated locator and never
    // scans for it or skips unknown options.
    switch (cfg->geneve_locator) {
    case GENEVE_LOCATOR_PORT:
        if (geneve_opt_len != 0 || geneve_critical)
            return TC_ACT_OK;
        if (dst_port < geneve_port_base)
            return TC_ACT_OK;
        slot_id = dst_port - geneve_port_base;
        received_vni = wire_vni;
        break;
    case GENEVE_LOCATOR_VNI:
        if (dst_port != GENEVE_PORT || geneve_opt_len != 0 ||
            geneve_critical)
            return TC_ACT_OK;
        slot_id = wire_vni >> GENEVE_VNI_LOCATOR_BITS;
        received_vni = wire_vni & GENEVE_VNI_VALUE_MASK;
        break;
    case GENEVE_LOCATOR_TLV: {
        if (dst_port != GENEVE_PORT ||
            geneve_opt_len != GENEVE_TLV_LOCATOR_LEN)
            return TC_ACT_OK;
        struct geneve_opt_hdr *locator = (void *)(geneve + 1);
        if ((void *)(locator + 1) > data_end ||
            (void *)((char *)locator + GENEVE_TLV_LOCATOR_LEN) > data_end)
            return TC_ACT_OK;
        if (locator->opt_class != bpf_htons(cfg->geneve_tlv_class) ||
            locator->type != cfg->geneve_tlv_type ||
            (locator->rsvd_len & 0xe0) != 0 ||
            (locator->rsvd_len & 0x1f) != 1)
            return TC_ACT_OK;
        if (geneve_critical != !!(locator->type & 0x80))
            return TC_ACT_OK;
        __be32 locator_data = 0;
        __bpf_memcpy(&locator_data, (void *)(locator + 1),
                     sizeof(locator_data));
        slot_id = bpf_ntohl(locator_data);
        received_vni = wire_vni;
        break;
    }
    default:
        return TC_ACT_OK;
    }

    if (slot_id >= n_ports)
        return TC_ACT_OK;

    // Get slot config and perform the common authenticated return checks.
    struct slot_item *slot = bpf_map_lookup_elem(&slots, &slot_id);
    __u64 generation = stats_generation(slot_id);
    if (!slot || is_slot_free(slot->inner_ip) || slot->ifindex == 0)
        return TC_ACT_OK;

    __u32 target_ifindex = slot->ifindex;
    __u32 expected_vni = slot->transit_geneve_vni;

    if (ip->saddr != bpf_htonl(slot->transit_gateway_ip))
        return TC_ACT_OK;

    // Verify VNI matches
    if (received_vni != expected_vni)
        return TC_ACT_OK;

    // Detect encap mode from proto_type
    __be16 inner_proto = geneve->proto_type;
    int is_eth = (inner_proto == bpf_htons(ETH_P_TEB));

    // Calculate decapsulation length (outer IP + UDP + GENEVE + options)
    __u32 decap_len = sizeof(struct iphdr) + sizeof(struct udphdr) +
                      sizeof(struct genevehdr) + geneve_opt_len;

    // Cache inner ETH h_proto before decap (will be lost after adjust_room)
    __be16 inner_eth_proto = 0;
    if (is_eth) {
        decap_len += sizeof(struct ethhdr);
        struct ethhdr *inner_eth = (void *)((char *)geneve + sizeof(struct genevehdr) + geneve_opt_len);
        if ((void *)(inner_eth + 1) > data_end)
            return TC_ACT_OK;
        inner_eth_proto = inner_eth->h_proto;
    }

    // Sanity check: decap_len must not exceed data beyond outer ETH
    if (sizeof(struct ethhdr) + decap_len >= skb->len)
        return TC_ACT_OK;

    __u32 pkt_len = skb->len - decap_len;

    // Remove encapsulation headers
    if (bpf_skb_adjust_room(skb, -(__s32)decap_len, BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_OK;

    // Re-fetch data pointers
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // After decap, outer ETH remains. Set correct MACs and proto.
    // Destination: port MAC (fixed or per-slot derived)
    get_port_mac(eth->h_dest, cfg, slot_id);
    __bpf_memcpy(eth->h_source, switch_mac, 6);
    // Set h_proto: for IP-over-GENEVE use GENEVE proto_type (L3 protocol),
    // for Ether-over-GENEVE use the cached inner ETH h_proto.
    if (is_eth)
        eth->h_proto = inner_eth_proto;
    else
        eth->h_proto = inner_proto;

    update_stats_transit_rx(slot_id, generation, pkt_len);

    return bpf_redirect(target_ifindex, 0);
}

// Force BTF generation for exported_u32 enum
static enum exported_u32 __attribute__((used)) __exported_u32_force_btf;

LICENSE("GPL");
