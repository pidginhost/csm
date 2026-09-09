/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CSM_RINGBUF_H
#define CSM_RINGBUF_H

struct csm_queue_stats {
    __u64 lost;
    __u64 submitted;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct csm_queue_stats);
    __uint(max_entries, 1);
} queue_stats SEC(".maps");

static __always_inline void csm_count_ring_event(int submitted) {
    __u32 zero = 0;
    struct csm_queue_stats *stats = bpf_map_lookup_elem(&queue_stats, &zero);
    if (!stats) {
        return;
    }
    /* Shared rings accept concurrent producers on different CPUs. */
    if (submitted) {
        __sync_fetch_and_add(&stats->submitted, 1);
    } else {
        __sync_fetch_and_add(&stats->lost, 1);
    }
}

static __always_inline void *csm_ringbuf_reserve(void *ring, __u64 size) {
    void *event = bpf_ringbuf_reserve(ring, size, 0);
    if (!event) {
        csm_count_ring_event(0);
    }
    return event;
}

static __always_inline void csm_ringbuf_submit(void *event) {
    bpf_ringbuf_submit(event, 0);
    csm_count_ring_event(1);
}

#endif
