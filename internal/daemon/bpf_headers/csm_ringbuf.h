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
    /* The consumer may run immediately after publication. */
    csm_count_ring_event(1);
    bpf_ringbuf_submit(event, 0);
}

/* Copies a record built elsewhere, such as per-CPU scratch, so the ring holds
 * only the bytes used. Counted before publication like csm_ringbuf_submit;
 * a failed copy moves its count to lost. */
static __always_inline long csm_ringbuf_output(void *ring, void *data, __u64 size) {
    __u32 zero = 0;
    struct csm_queue_stats *stats = bpf_map_lookup_elem(&queue_stats, &zero);
    if (stats) {
        __sync_fetch_and_add(&stats->submitted, 1);
    }
    long err = bpf_ringbuf_output(ring, data, size, 0);
    if (err && stats) {
        __sync_fetch_and_add(&stats->submitted, -1);
        __sync_fetch_and_add(&stats->lost, 1);
    }
    return err;
}

#endif
