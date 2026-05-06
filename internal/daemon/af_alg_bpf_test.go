//go:build linux && bpf

package daemon

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

// TestProbeBPFLSM_ReturnsBool is a "must not panic" smoke test on the
// shared probe. Skipped without root because BPF program loading is
// privileged.
func TestProbeBPFLSM_ReturnsBool(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF program load requires root / CAP_BPF")
	}
	_ = bpf.Probe().LSMAttach
}

// TestTryStartBPFLSM_AttachesAndShutsDown loads the AF_ALG LSM program,
// attaches it, runs the backend briefly, and confirms a clean shutdown.
// On a kernel without BPF LSM the load fails and the test reports
// bpf.ErrUnsupported, which the coordinator turns into "fall back to
// audit listener."
func TestTryStartBPFLSM_AttachesAndShutsDown(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF program load requires root / CAP_BPF")
	}
	ch := make(chan alert.Finding, 8)
	mon, err := tryStartBPFLSM(context.Background(), ch, &config.Config{})
	if err != nil {
		// Acceptable on hosts without BPF LSM trampoline support.
		t.Skipf("BPF LSM unavailable on this kernel: %v", err)
	}
	if mon == nil {
		t.Fatal("backend was nil with no error")
	}
	if mon.Mode() != "bpf-lsm" {
		t.Fatalf("Mode = %q, want bpf-lsm", mon.Mode())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	mon.Run(ctx)
}
