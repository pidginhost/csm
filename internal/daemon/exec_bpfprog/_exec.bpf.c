// CSM exec monitor. Tracepoint sched/sched_process_exec emits one event per
// userland process exec. Userspace decides which become findings; this
// program filters root early and skips emit when the ringbuf is full.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct exec_event {
    __u32 uid;
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];
    __u8  parent_comm[16];
    __u8  filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 19); // 512 KiB; spawn rate spikes at process trees
} events SEC(".maps");

// Force BTF emission of exec_event so bpf2go's -type flag finds it.
const struct exec_event *unused __attribute__((unused));

SEC("tracepoint/sched/sched_process_exec")
int csm_on_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 ug = bpf_get_current_uid_gid();
    __u32 uid = (__u32)(ug & 0xffffffff);
    if (uid == 0) {
        return 0;
    }

    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

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

    // Resolve __data_loc filename: low 16 bits = offset from ctx start.
    __u32 dl_filename = BPF_CORE_READ(ctx, __data_loc_filename);
    const char *fname = (const char *)((char *)ctx + (dl_filename & 0xffff));
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
