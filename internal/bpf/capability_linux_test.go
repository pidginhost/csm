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
	// Smoke assertion: at least one cap should be true on any modern kernel
	// the test fleet runs (>= 4.18). If they're all false the test bench has
	// a broken kernel image and we want to know.
	if !caps.Any() {
		t.Fatalf("Probe returned all-false on a Linux+bpf build; check kernel image: %+v", caps)
	}
	t.Logf("kernel caps: %+v", caps)
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
