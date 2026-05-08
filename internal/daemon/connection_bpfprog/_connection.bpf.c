// SPDX-License-Identifier: GPL-2.0-or-later
// CSM outbound-connection tracker. cgroup/connect4 + cgroup/connect6 hooks
// emit one struct conn_event per non-root connect syscall. Userspace policy
// (EvaluateConnection in internal/checks) decides whether to raise a finding;
// this program filters root early so the ringbuf does not fill on
// daemon-heavy hosts.
//
// Phase 4 adds an optional in-kernel deny path. When the userspace policy
// (in the `policy` map) sets enforce=1 and dry_run=0, a connect to a
// protected port from a UID not in the safe_uids map returns 0 (deny).
// In dry-run mode the same match emits decision=DECISION_DRY_RUN_DENY but
// returns 1 (allow) so userspace can observe the would-be-denied connects
// without affecting traffic.
//
// Uses the stable UAPI headers (linux/bpf.h, linux/in.h) -- no vmlinux.h or
// CO-RE relocations are needed because the only kernel struct read here is
// bpf_sock_addr, whose layout is fixed across kernel versions.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Stable Linux socket-family constants. Hardcoded because the kernel headers
// don't define them in BPF compilation context (no glibc).
#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define IPPROTO_TCP 6

// Decision codes emitted in conn_event.decision. Stable wire constants
// for userspace metrics labels.
#define DECISION_ALLOW          0
#define DECISION_DRY_RUN_DENY   1
#define DECISION_DENY           2

struct conn_event {
    __u32 uid;
    __u32 pid;
    __u32 family;
    __u32 dst_port;
    __u32 dst_ip4;     // network order, valid iff family == AF_INET
    __u8  dst_ip6[16]; // valid iff family == AF_INET6
    __u8  comm[16];
    __u32 decision;    // Phase 4: DECISION_* code
};

// policy_state is the userspace-controlled enforcement state. Single
// entry; loaded at daemon startup and refreshed on SIGHUP.
struct policy_state {
    __u32 enforce;          // 1 = enforce, 0 = passive (no deny in any mode)
    __u32 dry_run;          // 1 = log deny but allow, 0 = real deny
    __u32 protected_ports;  // count of valid entries in protected_ports map
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256 KiB
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct policy_state);
    __uint(max_entries, 1);
} policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 16);
} protected_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 65536);
} safe_uids SEC(".maps");

// Force BTF emission of conn_event so bpf2go's -type flag finds it.
const struct conn_event *unused __attribute__((unused));
const struct policy_state *unused_policy __attribute__((unused));

static __always_inline __u32 classify(__u32 uid, __u16 dst_port) {
    __u32 zero = 0;
    struct policy_state *p = bpf_map_lookup_elem(&policy, &zero);
    if (!p || !p->enforce) {
        return DECISION_ALLOW;
    }
    __u8 *port_hit = bpf_map_lookup_elem(&protected_ports, &dst_port);
    if (!port_hit) {
        return DECISION_ALLOW;
    }
    __u8 *safe = bpf_map_lookup_elem(&safe_uids, &uid);
    if (safe) {
        return DECISION_ALLOW;
    }
    if (p->dry_run) {
        return DECISION_DRY_RUN_DENY;
    }
    return DECISION_DENY;
}

static __always_inline int emit_event(struct bpf_sock_addr *ctx, __u32 family) {
    if (ctx->type != SOCK_STREAM || ctx->protocol != IPPROTO_TCP) {
        return 1; // allow, but keep UDP and other protocols out of TCP policy
    }

    __u64 ug = bpf_get_current_uid_gid();
    __u32 uid = (__u32)(ug & 0xffffffff);
    if (uid == 0) {
        return 1; // allow, do not emit
    }

    __u16 dst_port = bpf_ntohs(ctx->user_port);
    __u32 decision = classify(uid, dst_port);

    struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // Ringbuf full. Even when classify=DENY we cannot block silently;
        // failing open is the correct security trade-off here. The userspace
        // ringbuf-drops counter will surface the back-pressure.
        return 1;
    }

    e->uid = uid;
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->family = family;
    e->dst_port = dst_port;
    e->decision = decision;

    if (family == AF_INET) {
        e->dst_ip4 = ctx->user_ip4;
        __builtin_memset(e->dst_ip6, 0, sizeof(e->dst_ip6));
    } else {
        e->dst_ip4 = 0;
        __builtin_memcpy(e->dst_ip6, ctx->user_ip6, sizeof(e->dst_ip6));
    }

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    if (decision == DECISION_DENY) {
        return 0;
    }
    return 1;
}

SEC("cgroup/connect4")
int csm_connect4(struct bpf_sock_addr *ctx) {
    return emit_event(ctx, AF_INET);
}

SEC("cgroup/connect6")
int csm_connect6(struct bpf_sock_addr *ctx) {
    return emit_event(ctx, AF_INET6);
}

char LICENSE[] SEC("license") = "GPL";
