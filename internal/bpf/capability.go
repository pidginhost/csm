package bpf

import "sync"

// Capabilities reports which BPF program types the running kernel can
// actually load and attach. Populated once at daemon startup by Probe.
//
// Each field maps to a kernel feature, not a CSM feature: a single CSM
// feature (e.g. AF_ALG Phase B) may need multiple capability bits
// (LSMAttach + Ringbuf).
type Capabilities struct {
	LSMAttach  bool // BPF LSM programs can attach (kernel >= 5.7 with BPF LSM trampoline)
	CgroupSock bool // BPF_PROG_TYPE_CGROUP_SOCK_ADDR can attach to cgroup/connect4 (>= 4.10)
	Tracepoint bool // BPF_PROG_TYPE_TRACEPOINT can attach to sched/sched_process_exec (>= 4.7)
	Ringbuf    bool // BPF_MAP_TYPE_RINGBUF available (>= 5.8)
}

// Any reports whether at least one capability is true. Used by callers that
// only need to know "any BPF surface is usable" before deciding on legacy
// vs auto.
func (c Capabilities) Any() bool {
	return c.LSMAttach || c.CgroupSock || c.Tracepoint || c.Ringbuf
}

var (
	probeOnce   sync.Once
	probeResult Capabilities
)

// Probe returns the cached BPF capability result for this process. The first
// call performs the privileged load/attach probes; later calls return the same
// value without touching the kernel again.
func Probe() Capabilities {
	probeOnce.Do(func() {
		probeResult = probeKernel()
	})
	return probeResult
}
