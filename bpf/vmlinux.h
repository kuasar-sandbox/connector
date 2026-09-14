#ifndef __VMLINUX_H__
#define __VMLINUX_H__

// Basic types
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;
typedef __u16 __sum16;

#ifndef __packed
#define __packed __attribute__((packed))
#endif

struct bpf_spin_lock { __u32 val; };

// Ethernet header
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __packed;

// ARP header
struct arphdr {
    __be16 ar_hrd;     // format of hardware address
    __be16 ar_pro;     // format of protocol address
    __u8   ar_hln;     // length of hardware address
    __u8   ar_pln;     // length of protocol address
    __be16 ar_op;      // ARP opcode
} __packed;

// ARP payload for Ethernet/IPv4
struct arp_eth_payload {
    unsigned char ar_sha[6];  // sender hardware address
    __be32        ar_sip;     // sender IP address
    unsigned char ar_tha[6];  // target hardware address
    __be32        ar_tip;     // target IP address
} __packed;

// IP header
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 ihl:4,
         version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 version:4,
         ihl:4;
#else
    __u8 ihl:4,
         version:4;
#endif
    __u8  tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
} __packed;

// IPv6 address
struct in6_addr {
    union {
        __u8  u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    };
};

// IPv6 header
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 priority:4,
         version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 version:4,
         priority:4;
#else
    __u8 priority:4,
         version:4;
#endif
    __u8  flow_lbl[3];
    __be16 payload_len;
    __u8  nexthdr;
    __u8  hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
} __packed;

// UDP header
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __packed;

// GENEVE header (RFC 8926)
struct genevehdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 opt_len:6,
         ver:2;
    __u8 rsvd1:6,
         critical:1,
         oam:1;
#else
    __u8 ver:2,
         opt_len:6;
    __u8 oam:1,
         critical:1,
         rsvd1:6;
#endif
    __be16 proto_type;
    __u8 vni[3];
    __u8 rsvd2;
} __packed;

// TC __sk_buff (skb representation for BPF)
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 data_meta;
    // flow_keys and tstamp omitted for brevity
};

// BPF context for TC programs
#define BPF_F_INGRESS (1ULL << 0)

// FIB lookup parameters (for bpf_fib_lookup helper)
struct bpf_fib_lookup {
    __u8  family;        // AF_INET=2, AF_INET6=10
    __u8  l4_protocol;
    __be16 sport;
    __be16 dport;
    __u16 tot_len;       // total length of IP packet
    __u32 ifindex;       // input interface
    union {
        __u32 tos;       // IPv4
        __be32 flowinfo; // IPv6
    };
    union {
        __be32 ipv4_src;
        __u32  ipv6_src[4];
    };
    union {
        __be32 ipv4_dst;
        __u32  ipv6_dst[4];
    };
    // output
    __be16 h_vlan_proto;
    __be16 h_vlan_TCI;
    __u8   smac[6];
    __u8   dmac[6];
};

// FIB lookup return codes
enum {
    BPF_FIB_LKUP_RET_SUCCESS = 0,
    BPF_FIB_LKUP_RET_BLACKHOLE = 1,
    BPF_FIB_LKUP_RET_UNREACHABLE = 2,
    BPF_FIB_LKUP_RET_PROHIBIT = 3,
    BPF_FIB_LKUP_RET_NOT_FWDED = 4,
    BPF_FIB_LKUP_RET_FWD_DISABLED = 5,
    BPF_FIB_LKUP_RET_UNSUPP_LWT = 6,
    BPF_FIB_LKUP_RET_NO_NEIGH = 7,
    BPF_FIB_LKUP_RET_FRAG_NEEDED = 8,
};

#endif /* __VMLINUX_H__ */
