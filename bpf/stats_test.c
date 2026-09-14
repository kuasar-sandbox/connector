// SPDX-License-Identifier: GPL-2.0-only
// Kernel regression entry for a packet whose counter generation was captured
// before an attach reset. Uses the production counter helper without copying it.
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "common.h"
#include "stats.h"

SEC("tc")
int late_stats_write(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    if (data + 24 > end)
        return TC_ACT_SHOT;
    __u64 generation;
    __bpf_memcpy(&generation, data + 16, sizeof(generation));
    update_stats_mgmt_tx(0, generation, skb->len);
    return TC_ACT_OK;
}
LICENSE("GPL");
