// CSM sensitive-file write monitor. lsm/file_permission hook fires on every
// permission check; we filter for MAY_WRITE and look up (dev, ino) in the
// watched map populated by userspace at startup. Detection-only: returns
// the original ret value on every path.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAY_WRITE 0x2

struct fileid {
    __u64 dev;
    __u64 ino;
};

struct sensitive_event {
    __u32 uid;
    __u32 pid;
    __u32 mask;
    __u64 dev;
    __u64 ino;
    __u8  comm[16];
};

// watched is a hash keyed by (dev, ino). Value is unused; presence is the
// signal. Userspace populates this at startup and refreshes on a timer.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fileid);
    __type(value, __u32);
    __uint(max_entries, 4096);
} watched SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 17); // 128 KiB
} events SEC(".maps");

// Force BTF emission of sensitive_event so bpf2go's -type flag finds it.
const struct sensitive_event *unused __attribute__((unused));

SEC("lsm/file_permission")
int BPF_PROG(csm_file_perm, struct file *file, int mask, int ret) {
    if (ret != 0) {
        return ret;
    }
    if (!(mask & MAY_WRITE)) {
        return 0;
    }

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) {
        return 0;
    }

    struct fileid key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = BPF_CORE_READ(inode, i_sb, s_dev);

    __u32 *hit = bpf_map_lookup_elem(&watched, &key);
    if (!hit) {
        return 0;
    }

    struct sensitive_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->uid  = (__u32)(bpf_get_current_uid_gid() & 0xffffffff);
    e->pid  = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->mask = (__u32)mask;
    e->dev  = key.dev;
    e->ino  = key.ino;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0; // detection-only
}

char LICENSE[] SEC("license") = "GPL";
