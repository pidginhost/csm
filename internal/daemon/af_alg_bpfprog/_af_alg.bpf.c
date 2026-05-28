// SPDX-License-Identifier: GPL-2.0-or-later
// CSM AF_ALG (CVE-2026-31431, "Copy Fail") kernel-side deny + emit. The LSM
// socket_create hook fires before the kernel allocates the AF_ALG socket
// struct; returning -EPERM here refuses the syscall without giving the
// vulnerable code path a chance to run.
//
// Userspace consumer (internal/daemon/af_alg_bpf.go) reads events from the
// ringbuf and feeds them to reactToAFAlgEvent for kill + quarantine, the
// same reaction the audit-log fallback already uses.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define AF_ALG 38
#define EPERM  1

struct af_alg_event {
    __u32 uid;
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];
    __u8  parent_comm[16];
    __u8  exe[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); // 64 KiB; AF_ALG attempts are rare
} events SEC(".maps");

// Force BTF emission of af_alg_event so bpf2go's -type flag finds it.
const struct af_alg_event *unused __attribute__((unused));

SEC("lsm/socket_create")
int BPF_PROG(csm_block_af_alg, int family, int type, int protocol, int kern, int ret) {
    if (ret != 0) {
        return ret;
    }
    if (family != AF_ALG) {
        return 0;
    }
    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffff);
    if (uid == 0) {
        return 0; // root keeps kcrypto access; userspace policy hardens
    }

    struct af_alg_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->uid = uid;
        e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        e->ppid = BPF_CORE_READ(task, real_parent, tgid);

        bpf_get_current_comm(&e->comm, sizeof(e->comm));

        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            bpf_probe_read_kernel_str(&e->parent_comm, sizeof(e->parent_comm),
                                       BPF_CORE_READ(parent, comm));
        } else {
            __builtin_memset(e->parent_comm, 0, sizeof(e->parent_comm));
        }

        // bpf_d_path() requires a PTR_TRUSTED struct path *. Chasing the
        // pointer with BPF_CORE_READ yields a scalar (probe-read return value),
        // which fails the verifier on kernel >=6.12 with
        //   R1 type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_
        // Direct field access on the trusted task_struct from
        // bpf_get_current_task_btf() propagates the trusted tag.
        struct mm_struct *mm = task->mm;
        if (mm) {
            struct file *exe_file = mm->exe_file;
            if (exe_file) {
                bpf_d_path(&exe_file->f_path, (char *)e->exe, sizeof(e->exe));
            } else {
                __builtin_memset(e->exe, 0, sizeof(e->exe));
            }
        } else {
            __builtin_memset(e->exe, 0, sizeof(e->exe));
        }

        bpf_ringbuf_submit(e, 0);
    }
    return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
