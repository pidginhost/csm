//go:build linux && bpf

package daemon

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// probeBPFLSM loads a no-op BPF LSM program attached to socket_create,
// then immediately detaches and closes it. The conclusive runtime check
// for BPF LSM availability — kernel config flags alone are insufficient
// because RHEL 8 sets CONFIG_BPF_LSM=y but lacks the trampoline runtime
// the verifier needs to attach LSM programs. Any load or attach error
// (kernel too old, BPF disabled at boot, missing BTF, missing LSM
// trampoline) is wrapped and returned so the operator log explains why
// CSM fell back to the audit listener.
func probeBPFLSM() error {
	probe := &ebpf.ProgramSpec{
		Name:       "csm_af_alg_probe",
		Type:       ebpf.LSM,
		AttachType: ebpf.AttachLSMMac,
		AttachTo:   "socket_create",
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	}

	prog, err := ebpf.NewProgram(probe)
	if err != nil {
		return fmt.Errorf("load BPF LSM probe: %w", err)
	}
	defer func() { _ = prog.Close() }()

	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		return fmt.Errorf("attach BPF LSM probe: %w", err)
	}
	return l.Close()
}

// tryStartBPFLSM is the bpf-tag implementation. It probes the kernel for
// BPF LSM support; if the probe succeeds, the architecture is ready for
// the real blocking program (Phase B in the plan) but until that lands we
// return errBPFPhaseBPending so the coordinator continues to use the
// audit-log listener. This keeps the build tag harmless to deploy: an
// operator who builds with -tags bpf does not lose detection coverage
// while Phase B is still being authored against an alma9 test bench.
func tryStartBPFLSM(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (AFAlgLiveMonitor, error) {
	if err := probeBPFLSM(); err != nil {
		return nil, err
	}
	return nil, errBPFPhaseBPending
}
