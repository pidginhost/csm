// SPDX-License-Identifier: GPL-2.0-or-later
// CSM placement monitor. A file written elsewhere and then renamed or
// hard-linked into a site never raises close-write at its new path, so
// lsm/inode_rename and lsm/inode_link report the inode and its new name.
// Inode hooks see the dentry, not a mount, and every bind mount of one
// superblock shares s_dev, so the program walks d_parent to the superblock
// root and userspace joins the names under that filesystem's whole mount.
// Detection-only: every hook returns the incoming ret.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../bpf_headers/csm_ringbuf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// The unrolled walk costs about 37 instructions a level. 64 keeps each
// program near 2.4k, under the 4096 cap kernels before 5.2 enforce.
#define PLACEMENT_MAX_DEPTH 64
#define PLACEMENT_PATH_MAX  4096
// NAME_MAX plus the terminating NUL.
#define PLACEMENT_NAME_MAX  256

#define PLACEMENT_RENAME 1
#define PLACEMENT_LINK   2

#define S_IFMT  00170000
#define S_IFREG 0100000
#define S_IFDIR 0040000

// Names are written leaf first, each NUL-terminated; depth counts them.
// truncated means the walk stopped before the superblock root.
struct placement_event {
    __u8  kind;
    __u8  is_dir;
    __u8  depth;
    __u8  truncated;
    __u32 pid;
    __u64 dev;
    __u64 ino;
    char  path[PLACEMENT_PATH_MAX];
};

// Keyed by the kernel's s_dev. Presence is the signal. Not named watched_*:
// bpf2go would emit a PlacementMapW... constant that gosec reads as "pw".
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u8);
    __uint(max_entries, 64);
} devs_watched SEC(".maps");

// Events are built here and copied out at their used length, so the ring
// holds a typical placement in about a hundred bytes, not the full 4 KiB.
// From 5.11, a kernel built with full, lazy or RT preemption runs this
// program with migration disabled but preemption enabled, and LSM programs
// have no recursion guard: a second rename or link on this CPU can start
// while a placement is mid-build. busy makes that second hook count itself
// lost instead of overwriting the first. The claim is add-then-check because
// exchange atomics need 5.12; a race can make both hooks count a loss, never
// both build.
struct placement_slot {
    __u32 busy;
    struct placement_event ev;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct placement_slot);
    __uint(max_entries, 1);
} scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

// Force BTF emission of placement_event so bpf2go's -type flag finds it.
const struct placement_event *unused __attribute__((unused));

// report emits the inode behind source under the name target will have.
static __always_inline void report(struct dentry *source, struct dentry *target, __u8 kind) {
    struct inode *inode = BPF_CORE_READ(source, d_inode);
    if (!inode) {
        return;
    }
    __u16 fmt = BPF_CORE_READ(inode, i_mode) & S_IFMT;
    if (fmt != S_IFREG && fmt != S_IFDIR) {
        return;
    }
    __u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    if (!bpf_map_lookup_elem(&devs_watched, &dev)) {
        return;
    }

    __u32 zero = 0;
    struct placement_slot *slot = bpf_map_lookup_elem(&scratch, &zero);
    if (!slot) {
        return;
    }
    __sync_fetch_and_add(&slot->busy, 1);
    if (*(volatile __u32 *)&slot->busy != 1) {
        __sync_fetch_and_add(&slot->busy, -1);
        csm_count_ring_event(0);
        return;
    }
    struct placement_event *e = &slot->ev;
    e->kind   = kind;
    e->is_dir = fmt == S_IFDIR;
    e->pid    = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->dev    = dev;
    e->ino    = BPF_CORE_READ(inode, i_ino);

    struct dentry *d = target;
    __u32 off = 0;
    __u8 depth = 0;
    __u8 at_root = 0;
#pragma unroll
    for (int i = 0; i <= PLACEMENT_MAX_DEPTH; i++) {
        struct dentry *parent = BPF_CORE_READ(d, d_parent);
        if (parent == d) {
            at_root = 1;
            break;
        }
        // The extra iteration only checks for the root after the last name.
        if (i == PLACEMENT_MAX_DEPTH || off > PLACEMENT_PATH_MAX - PLACEMENT_NAME_MAX) {
            break;
        }
        const unsigned char *name = BPF_CORE_READ(d, d_name.name);
        long n = bpf_probe_read_kernel_str(&e->path[off], PLACEMENT_NAME_MAX, name);
        if (n <= 0) {
            break;
        }
        off += n;
        depth++;
        d = parent;
    }
    e->depth     = depth;
    e->truncated = !at_root;
    // The clamp bounds the size for verifiers that do not track off.
    __u64 size = __builtin_offsetof(struct placement_event, path) + off;
    if (size > sizeof(*e)) {
        size = sizeof(*e);
    }
    csm_ringbuf_output(&events, e, size);
    __sync_fetch_and_add(&slot->busy, -1);
}

// For RENAME_EXCHANGE the core calls this hook once per direction with the
// arguments swapped, and the hook carries no flags, so both inodes arrive.
SEC("lsm/inode_rename")
int BPF_PROG(csm_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, int ret) {
    if (ret != 0) {
        return ret;
    }
    report(old_dentry, new_dentry, PLACEMENT_RENAME);
    return ret;
}

SEC("lsm/inode_link")
int BPF_PROG(csm_inode_link, struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry, int ret) {
    if (ret != 0) {
        return ret;
    }
    report(old_dentry, new_dentry, PLACEMENT_LINK);
    return ret;
}

char LICENSE[] SEC("license") = "GPL";
