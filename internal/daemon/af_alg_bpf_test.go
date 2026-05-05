//go:build linux && bpf

package daemon

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

// TestProbeBPFLSM_ReturnsBool is a "must not panic" smoke test. The
// shared probe in internal/bpf returns a bool indicating whether BPF
// LSM programs can attach on this kernel; we accept either value.
// Skipped without CAP_BPF / root because BPF program loading is
// privileged and the probe issues a real load+attach call.
func TestProbeBPFLSM_ReturnsBool(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF program load requires root / CAP_BPF")
	}
	_ = bpf.Probe().LSMAttach // any value is acceptable; the contract is "no panic"
}

// TestTryStartBPFLSM_PhaseBPendingPropagates documents the Phase A
// behaviour: when the kernel supports BPF LSM, tryStartBPFLSM still
// returns a non-nil error (errBPFPhaseBPending) so the coordinator
// falls back to the audit listener. When the probe fails, bpf.ErrUnsupported
// is returned instead. Both outcomes keep the audit fallback engaged
// while Phase B is unimplemented.
func TestTryStartBPFLSM_PhaseBPendingPropagates(t *testing.T) {
	mon, err := tryStartBPFLSM(context.Background(), make(chan alert.Finding), &config.Config{})
	if mon != nil {
		t.Fatalf("expected nil monitor while Phase B is pending, got %T", mon)
	}
	if err == nil {
		t.Fatal("expected non-nil error so coordinator falls back to audit")
	}
	if os.Geteuid() == 0 {
		// On a kernel that supports BPF LSM, the probe succeeds and the
		// returned error must be errBPFPhaseBPending so the operator log
		// distinguishes "kernel ready, code missing" from "kernel
		// unsupported." We cannot assert this unconditionally because
		// not every CI runner has BPF LSM, so the check only fires when
		// we are root AND the probe reports support.
		if bpf.Probe().LSMAttach && !errors.Is(err, errBPFPhaseBPending) {
			t.Fatalf("kernel supports BPF LSM but tryStartBPFLSM did not return errBPFPhaseBPending: %v", err)
		}
	}
}
