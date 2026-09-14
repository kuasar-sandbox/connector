#ifndef __COMMON_H__
#define __COMMON_H__

// BPF map flags (from include/uapi/linux/bpf.h)
#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif

#define MAX_PORTS 4096
#define MAX_MGMT_SVC 1024  // Max mgmt service NAT entries (per direction, per proto)
#define MAX_MGMT_CIDR_PER_SLOT 3
#define MAX_MGMT_CIDR_EXT      (MAX_MGMT_CIDR_PER_SLOT - 1)  // Extended array size (cold path)

// GENEVE locator and option limits. MAX_GENEVE_OPTS_LEN covers every wire
// option after the base header, including the generated 8-byte TLV locator.
#define MAX_GENEVE_OPTS_LEN      64
#define GENEVE_LOCATOR_PORT      0
#define GENEVE_LOCATOR_VNI       1
#define GENEVE_LOCATOR_TLV       2
#define GENEVE_VNI_LOCATOR_BITS  12
#define GENEVE_VNI_VALUE_MASK    0x0fff
#define GENEVE_TLV_LOCATOR_LEN   8

_Static_assert(MAX_PORTS == (1U << GENEVE_VNI_LOCATOR_BITS),
               "MAX_PORTS must match the fixed GENEVE VNI locator layout");

// inner_ip empty slot definitions (supports async initialization)
#define INNER_IP_FREE       0
#define INNER_IP_RESERVED   0xFFFFFFFF
#define is_slot_free(ip)    ((ip) == INNER_IP_FREE || (ip) == INNER_IP_RESERVED)

#define ETH_ALEN 6

// Port MAC derivation:
// byte4 = ((switch_mac[4] ^ 0x80) & 0x80) | (slot_id >> 8)
// byte5 = slot_id & 0xFF
#define PORT_MAC_XOR       0x80    // byte4 MSB flip mask (ensures port MAC != switch_mac)
#define MGMT_MAC_ID_BASE   0x7FF0  // Management MAC id base (0x7FF0 + mgmt_idx)

// Port kinds stored in slot_item.mode
// Existing pre-mode-bit slots have mode==0 → veth (backward compatible default).
#define PORT_KIND_VETH 0
#define PORT_KIND_TAP  1
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define ETH_P_IPV6 0x86DD
#define ETH_P_TEB 0x6558

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// ARP opcodes
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

// GENEVE standard port
#define GENEVE_PORT 6081

// Address families
#define AF_INET 2

// Action codes
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_REDIRECT 7

// Nexthop parameters for bpf_redirect_neigh
struct bpf_redir_neigh {
    __u32 nh_family;
    union {
        __be32 ipv4_nh;
        __u32  ipv6_nh[4];
    };
};

// Management service NAT entry (key/value for the global svc maps).
//
// Layers a stateless, port-aware VIP<->target translation on top of the
// inner_ip<->floating_ip mgmt NAT. The maps are switch-global (identical for
// every slot), so they live outside the per-slot slot_item:
//   mgmt_svc_fwd: {VIP, vport, proto}    -> {target_ip, target_port}  (egress nx)
//   mgmt_svc_rev: {target_ip, tport, proto} -> {VIP, vport}           (ingress mx)
//
// All addresses/ports are stored in NETWORK byte order so the datapath can
// compare/write them directly against the packet without byte swaps. Userspace
// must zero _pad — it is part of the hash key.
struct svc_key {
    __u32 ip;     // network byte order (matches iphdr.daddr / iphdr.saddr)
    __u16 port;   // network byte order (matches L4 dest/source port)
    __u8  proto;  // IPPROTO_TCP or IPPROTO_UDP
    __u8  _pad;   // must be zero (part of the hash key)
};  // Total: 8 bytes

struct svc_val {
    __u32 ip;     // network byte order
    __u16 port;   // network byte order
    __u16 _pad;   // reserved
};  // Total: 8 bytes

// Serialized opaque GENEVE options for one slot. The generated TLV locator is
// not stored here: the data path prepends it from switch_config when needed.
struct geneve_opts_value {
    __u8 len;
    __u8 critical;
    __u16 reserved;
    __u8 data[MAX_GENEVE_OPTS_LEN];
};  // Total: 68 bytes

// RFC 8926 option header. The low 5 bits of rsvd_len contain the data length
// in 4-byte words; the high 3 bits are reserved and must be zero.
struct geneve_opt_hdr {
    __be16 opt_class;
    __u8 type;
    __u8 rsvd_len;
} __attribute__((packed));

// Management CIDR entry
struct mgmt_cidr {
    __u32 ip;      // Management service IP (e.g., 169.254.169.254)
    __u32 mask;    // Netmask (e.g., 0xffffffff for /32)
    __u32 ifindex; // Management port peer (<sw>-mX) ifindex in switch netns
    __u8  mgmt_mac[6]; // MAC address for ARP replies to mgmt traffic
    __u8  _pad[2];
};  // Total: 20 bytes

// Slot configuration - indexed by slot_id (0 to n_ports-1)
// floating_ip = config.floating_ip_base + slot_id
// geneve_port = config.geneve_port_base + slot_id
//
// Cache line optimized layout:
// - Cache Line 0 (64 bytes): All hot path fields + first mgmt_cidr
// - Cache Line 1 (44 bytes): Extended mgmt_cidrs (cold path)
struct slot_item {
    // ═══════════════════════════════════════════════════════════
    // Cache Line 0 (64 bytes) - All hot path fields
    // ═══════════════════════════════════════════════════════════
    __u32 ifindex;            // offset 0  - Sandbox port peer ifindex, checked every packet
    __u32 inner_ip;           // offset 4  - Sandbox internal IP, 0/0xFFFFFFFF = free
    __u32 transit_ifindex;    // offset 8  - Transit device ifindex (GENEVE encap)
    __u32 transit_ip;         // offset 12 - GENEVE outer source IP
    __u32 transit_gateway_ip; // offset 16 - GENEVE outer destination IP
    __u32 transit_geneve_vni; // offset 20 - GENEVE VNI
    __u8  transit_mac[6];     // offset 24 - Transit destination MAC
    __u8  mode;               // offset 30 - Port kind: 0=veth (default), 1=tap (PORT_KIND_*)
    __u8  geneve_opts_len;    // offset 31 - Opaque option bytes; 0 skips map lookup
    __u32 mgmt_cidr_count;    // offset 32 - Number of management routes
    struct mgmt_cidr mgmt_cidrs_0;  // offset 36-55 (20B) - Inline first mgmt_cidr (hot entry)
    __u8  _pad_cl0[8];        // offset 56-63 - Pad to 64 bytes

    // ═══════════════════════════════════════════════════════════
    // Cache Line 1 (44 bytes) - Extended mgmt_cidrs (cold path)
    // ═══════════════════════════════════════════════════════════
    struct mgmt_cidr mgmt_cidrs_ext[MAX_MGMT_CIDR_EXT]; // offset 64-103 (40B)
    __u32 stats_ready;        // offset 104-107 - Userspace: current attach reset confirmed
};  // Total: 108 bytes

// Global switch configuration (kernel-side only, 40 bytes)
// Userspace metadata moved to switch_metadata in separate map
struct switch_config {
    __u8  switch_mac[6];      // Virtual MAC for ARP replies
    __u16 _pad;
    __u32 n_ports;            // Total number of ports
    __u32 floating_ip_base;   // Floating IP base (e.g., 100.100.96.0)
    __u32 geneve_port_base;   // GENEVE UDP port base (e.g., 50000)
    __u8  geneve_encap_eth;   // 1 = Ether-over-GENEVE, 0 = IP-over-GENEVE (default)
    __u8  _pad3[3];           // Alignment
    __u32 transit_nexthop;    // transit-dev L3 nexthop IP, 0 = FIB lookup
    __u8  port_mac[6];        // Port MAC: all-zero = per-port derivation, non-zero = fixed value
    __u8  _pad4[2];           // Alignment
    __u8  geneve_locator;     // GENEVE_LOCATOR_*; zero is legacy port mode
    __u8  geneve_tlv_type;    // Exact 8-bit wire type, including critical bit
    __u16 geneve_tlv_class;   // Host-order option class
};  // Total: 40 bytes

// Userspace-only metadata (stored in separate 'metadata' map as JSON)
// eBPF programs do not read these fields
#define METADATA_MAX_SIZE 4096

// Per-slot traffic statistics (from sandbox perspective)
// rx = traffic received by sandbox
// tx = traffic sent by sandbox
// mgmt = management plane traffic, transit = external/GENEVE traffic
struct slot_stats {
    struct bpf_spin_lock lock;
    __u32 _pad;
    __u64 generation; // Internal counter instance, advanced under the control lock
    __u64 mgmt_rx_packets;
    __u64 mgmt_rx_bytes;
    __u64 mgmt_tx_packets;
    __u64 mgmt_tx_bytes;
    __u64 transit_rx_packets;
    __u64 transit_rx_bytes;
    __u64 transit_tx_packets;
    __u64 transit_tx_bytes;
};

// Enum for exporting constants to Go via bpf2go -type
enum exported_u32 {
    __MAX_PORTS = MAX_PORTS,
    __MAX_MGMT_CIDR_PER_SLOT = MAX_MGMT_CIDR_PER_SLOT,
    __INNER_IP_FREE = INNER_IP_FREE,
    __INNER_IP_RESERVED = INNER_IP_RESERVED,
    __PORT_KIND_VETH = PORT_KIND_VETH,
    __PORT_KIND_TAP = PORT_KIND_TAP,
    __MAX_GENEVE_OPTS_LEN = MAX_GENEVE_OPTS_LEN,
    __GENEVE_PORT = GENEVE_PORT,
    __GENEVE_LOCATOR_PORT = GENEVE_LOCATOR_PORT,
    __GENEVE_LOCATOR_VNI = GENEVE_LOCATOR_VNI,
    __GENEVE_LOCATOR_TLV = GENEVE_LOCATOR_TLV,
    __GENEVE_VNI_LOCATOR_BITS = GENEVE_VNI_LOCATOR_BITS,
    __GENEVE_VNI_VALUE_MASK = GENEVE_VNI_VALUE_MASK,
};

#endif /* __COMMON_H__ */
