//go:build linux && bpf

package bpf

import (
	"os"
	"testing"
)

func TestProbeOnLinuxBPF(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF probe needs CAP_BPF / root; skipping in unprivileged env")
	}
	caps := Probe()
	t.Logf("kernel caps: %+v", caps)

	// The cached answer must be what the kernel says now, on any kernel:
	// a stale or zeroed cache would send every coordinator to the wrong
	// backend.
	if fresh := probeKernel(); caps != fresh {
		t.Fatalf("Probe() = %+v, fresh kernel probe = %+v", caps, fresh)
	}
}

func TestProbeIsIdempotent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs CAP_BPF")
	}
	a := Probe()
	b := Probe()
	if a != b {
		t.Fatalf("Probe is not idempotent: %+v vs %+v", a, b)
	}
}
