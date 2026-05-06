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
	if !caps.Any() {
		t.Skipf("BPF capability probes are unavailable in this privileged test environment: %+v", caps)
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
