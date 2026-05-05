//go:build linux && bpf

package bpf

import (
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// Probe loads and attaches a one-instruction throwaway program of each BPF
// type CSM may use, reporting which ones the kernel accepts. The probe is
// conclusive for every program type where the eventual backend requires an
// attachment: it does not read /proc/config.gz or /sys/kernel/btf/vmlinux,
// because RHEL 8 sets CONFIG_BPF_LSM=y while lacking the trampoline runtime
// the verifier needs to attach LSM programs.
//
// Each sub-probe loads the program, attaches it where attach is required,
// immediately detaches and closes it. Failures (kernel too old, BPF disabled
// at boot, missing BTF, missing trampoline, no cgroup v2 mount) are swallowed:
// the corresponding cap is left false. Probe() in capability.go caches this
// result for the process lifetime.
func probeKernel() Capabilities {
	return Capabilities{
		LSMAttach:  probeLSM(),
		CgroupSock: probeCgroupSock(),
		Tracepoint: probeTracepoint(),
		Ringbuf:    probeRingbuf(),
	}
}

func probeLSM() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:       "csm_cap_lsm",
		Type:       ebpf.LSM,
		AttachType: ebpf.AttachLSMMac,
		AttachTo:   "socket_create",
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return false
	}
	defer prog.Close()
	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		return false
	}
	return l.Close() == nil
}

func probeCgroupSock() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:       "csm_cap_cgsock",
		Type:       ebpf.CGroupSockAddr,
		AttachType: ebpf.AttachCGroupInet4Connect,
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		},
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	cgroupPath := firstCgroupV2Path()
	if cgroupPath == "" {
		return false
	}
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	})
	if err != nil {
		return false
	}
	return l.Close() == nil
}

func firstCgroupV2Path() string {
	for _, p := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"} {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return ""
}

func probeTracepoint() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:    "csm_cap_tp",
		Type:    ebpf.TracePoint,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return false
	}
	defer prog.Close()
	l, err := link.Tracepoint("sched", "sched_process_exec", prog, nil)
	if err != nil {
		return false
	}
	return l.Close() == nil
}

func probeRingbuf() bool {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	})
	if err != nil {
		return false
	}
	return m.Close() == nil
}
