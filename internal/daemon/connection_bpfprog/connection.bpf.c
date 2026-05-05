// CSM outbound-connection tracker. cgroup/connect4 + cgroup/connect6 hooks
// emit one struct conn_event per non-root connect syscall. Userspace policy
// (EvaluateConnection in internal/checks) decides whether to raise a finding;
// this program only filters root early so the ringbuf does not fill on
// daemon-heavy hosts.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10

struct conn_event {
    __u32 uid;
    __u32 pid;
    __u32 family;
    __u32 dst_port;
    __u32 dst_ip4;     // network order, valid iff family == AF_INET
    __u8  dst_ip6[16]; // valid iff family == AF_INET6
    __u8  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256 KiB
} events SEC(".maps");

static __always_inline int emit_event(struct bpf_sock_addr *ctx, __u32 family) {
    __u64 ug = bpf_get_current_uid_gid();
    __u32 uid = (__u32)(ug & 0xffffffff);
    if (uid == 0) {
        return 1; // allow, do not emit
    }

    struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 1; // ringbuf full; do not stall the connect
    }

    e->uid = uid;
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->family = family;
    e->dst_port = bpf_ntohs(ctx->user_port);

    if (family == AF_INET) {
        e->dst_ip4 = ctx->user_ip4;
        __builtin_memset(e->dst_ip6, 0, sizeof(e->dst_ip6));
    } else {
        e->dst_ip4 = 0;
        // user_ip6 is __be32[4]; copy 16 bytes verbatim.
        __builtin_memcpy(e->dst_ip6, ctx->user_ip6, sizeof(e->dst_ip6));
    }

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
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
