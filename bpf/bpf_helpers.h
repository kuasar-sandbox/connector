#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

// Attribute definitions
#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

// offsetof macro
#ifndef offsetof
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#endif

// BPF helper function signatures
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static long (*bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 4;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;
static long (*bpf_redirect)(int ifindex, __u64 flags) = (void *) 23;
static long (*bpf_clone_redirect)(void *skb, __u32 ifindex, __u64 flags) = (void *) 13;
static long (*bpf_skb_store_bytes)(void *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *) 9;
static long (*bpf_l3_csum_replace)(void *skb, __u32 offset, __u64 from, __u64 to, __u64 size) = (void *) 10;
static long (*bpf_l4_csum_replace)(void *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) = (void *) 11;
static long (*bpf_skb_change_tail)(void *skb, __u32 len, __u64 flags) = (void *) 38;
static long (*bpf_skb_change_head)(void *skb, __u32 len, __u64 flags) = (void *) 43;
static long (*bpf_skb_adjust_room)(void *skb, __s32 len_diff, __u32 mode, __u64 flags) = (void *) 50;
static long (*bpf_skb_pull_data)(void *skb, __u32 len) = (void *) 39;
static __u32 (*bpf_get_smp_processor_id)(void) = (void *) 8;
static long (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __wsum seed) = (void *) 28;
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags) = (void *) 69;
static long (*bpf_redirect_neigh)(__u32 ifindex, void *params, int plen, __u64 flags) = (void *) 152;

static long (*bpf_spin_lock)(struct bpf_spin_lock *lock) = (void *) 93;
static long (*bpf_spin_unlock)(struct bpf_spin_lock *lock) = (void *) 94;

// Map definition macro for newer libbpf style
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

// BPF_MAP_TYPE constants
enum {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
};

// skb_adjust_room modes
enum {
    BPF_ADJ_ROOM_NET = 0,
    BPF_ADJ_ROOM_MAC = 1,
};

// skb_adjust_room flags
enum {
    BPF_F_ADJ_ROOM_FIXED_GSO = (1ULL << 0),
    BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 = (1ULL << 1),
    BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 = (1ULL << 2),
    BPF_F_ADJ_ROOM_ENCAP_L4_GRE = (1ULL << 3),
    BPF_F_ADJ_ROOM_ENCAP_L4_UDP = (1ULL << 4),
    BPF_F_ADJ_ROOM_NO_CSUM_RESET = (1ULL << 5),
};

// BPF_F_ADJ_ROOM_ENCAP_L2(len) encodes inner L2 header length
#define BPF_ADJ_ROOM_ENCAP_L2_MASK  0xff
#define BPF_ADJ_ROOM_ENCAP_L2_SHIFT 56
#define BPF_F_ADJ_ROOM_ENCAP_L2(len) \
    (((__u64)(len) & BPF_ADJ_ROOM_ENCAP_L2_MASK) << BPF_ADJ_ROOM_ENCAP_L2_SHIFT)

// L4 csum replace flags
#define BPF_F_PSEUDO_HDR (1ULL << 4)

// Map flags
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

// License
#define LICENSE(s) char _license[] SEC("license") = s

// Barriers and memory ordering
#define barrier() __asm__ __volatile__("": : :"memory")

// Inline memset/memcpy
static __always_inline void __bpf_memset(void *dst, int c, __u32 len)
{
    __u8 *d = dst;
    for (__u32 i = 0; i < len; i++)
        d[i] = c;
}

static __always_inline void __bpf_memcpy(void *dst, const void *src, __u32 len)
{
    __u8 *d = dst;
    const __u8 *s = src;
    for (__u32 i = 0; i < len; i++)
        d[i] = s[i];
}

#define __bpf_htons(x) __builtin_bswap16(x)
#define __bpf_ntohs(x) __builtin_bswap16(x)
#define __bpf_htonl(x) __builtin_bswap32(x)
#define __bpf_ntohl(x) __builtin_bswap32(x)

#define bpf_htons(x) __bpf_htons(x)
#define bpf_ntohs(x) __bpf_ntohs(x)
#define bpf_htonl(x) __bpf_htonl(x)
#define bpf_ntohl(x) __bpf_ntohl(x)

#endif /* __BPF_HELPERS_H__ */
