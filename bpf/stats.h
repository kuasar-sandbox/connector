#ifndef __STATS_H__
#define __STATS_H__

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u32);
    __type(value, struct slot_stats);
} stats SEC(".maps");

// Capture before reading any attachment fields. Reset publishes a new
// generation under this lock only after all new attachment fields are ready.
static __always_inline __u64 stats_generation(__u32 slot_id)
{
    struct slot_stats *s = bpf_map_lookup_elem(&stats, &slot_id);
    if (!s)
        return 0;
    bpf_spin_lock(&s->lock);
    __u64 generation = s->generation;
    bpf_spin_unlock(&s->lock);
    return generation;
}

static __always_inline void update_stats_mgmt_tx(__u32 slot_id, __u64 generation, __u32 pkt_len)
{
    struct slot_stats *s = bpf_map_lookup_elem(&stats, &slot_id);
    if (s) {
        bpf_spin_lock(&s->lock);
        if (generation && s->generation == generation) {
            s->mgmt_tx_packets++;
            s->mgmt_tx_bytes += pkt_len;
        }
        bpf_spin_unlock(&s->lock);
    }
}

static __always_inline void update_stats_mgmt_rx(__u32 slot_id, __u64 generation, __u32 pkt_len)
{
    struct slot_stats *s = bpf_map_lookup_elem(&stats, &slot_id);
    if (s) {
        bpf_spin_lock(&s->lock);
        if (generation && s->generation == generation) {
            s->mgmt_rx_packets++;
            s->mgmt_rx_bytes += pkt_len;
        }
        bpf_spin_unlock(&s->lock);
    }
}

static __always_inline void update_stats_transit_tx(__u32 slot_id, __u64 generation, __u32 pkt_len)
{
    struct slot_stats *s = bpf_map_lookup_elem(&stats, &slot_id);
    if (s) {
        bpf_spin_lock(&s->lock);
        if (generation && s->generation == generation) {
            s->transit_tx_packets++;
            s->transit_tx_bytes += pkt_len;
        }
        bpf_spin_unlock(&s->lock);
    }
}

static __always_inline void update_stats_transit_rx(__u32 slot_id, __u64 generation, __u32 pkt_len)
{
    struct slot_stats *s = bpf_map_lookup_elem(&stats, &slot_id);
    if (s) {
        bpf_spin_lock(&s->lock);
        if (generation && s->generation == generation) {
            s->transit_rx_packets++;
            s->transit_rx_bytes += pkt_len;
        }
        bpf_spin_unlock(&s->lock);
    }
}

#endif
