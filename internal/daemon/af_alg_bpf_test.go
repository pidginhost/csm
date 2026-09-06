//go:build linux && bpf

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

func TestProbeBPFLSMMatchesAttachment(t *testing.T) {
	caps := bpf.Probe()
	mon, err := tryStartBPFLSM(context.Background(), make(chan alert.Finding, 8), &config.Config{})
	if !caps.LSMAttach || !caps.Ringbuf {
		if !errors.Is(err, bpf.ErrUnsupported) || mon != nil {
			t.Fatalf("unsupported capabilities: monitor=%v err=%v", mon, err)
		}
		return
	}
	if err != nil || mon == nil {
		t.Fatalf("advertised BPF capability did not attach: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mon.Run(ctx)
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

func TestDecodeAFAlgEventStampsDetectionTime(t *testing.T) {
	before := time.Now()
	ev, err := decodeAFAlgEvent(make([]byte, 300))
	if err != nil {
		t.Fatal(err)
	}
	var sec, nsec int64
	if _, err := fmt.Sscanf(ev.Timestamp, "%d.%d", &sec, &nsec); err != nil {
		t.Fatalf("parse BPF event timestamp %q: %v", ev.Timestamp, err)
	}
	detectedAt := time.Unix(sec, nsec)
	if detectedAt.Before(before) || detectedAt.After(time.Now()) {
		t.Fatalf("BPF event timestamp = %v, want a current detection time", detectedAt)
	}
}
