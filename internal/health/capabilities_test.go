package health

import (
	"testing"

	"github.com/pidginhost/csm/internal/bpf"
)

// TestBPFCapabilityStringsAppearWhenProbed asserts that the dynamic BPF
// capability strings stay in sync with bpf.Probe(): a string is present iff
// the matching probe field is true. Runs on every platform; on macOS the
// stub returns all-false and the test verifies absence.
func TestBPFCapabilityStringsAppearWhenProbed(t *testing.T) {
	caps := Capabilities()
	saw := map[string]bool{}
	for _, c := range caps {
		saw[c] = true
	}
	probed := bpfCapabilities()
	if probed.LSMAttach && !saw["bpf-lsm-attach"] {
		t.Error("LSMAttach probed true but capability string missing")
	}
	if probed.CgroupSock && !saw["bpf-cgroup-sock"] {
		t.Error("CgroupSock probed true but capability string missing")
	}
	if probed.Tracepoint && !saw["bpf-tracepoint"] {
		t.Error("Tracepoint probed true but capability string missing")
	}
	if probed.Ringbuf && !saw["bpf-ringbuf"] {
		t.Error("Ringbuf probed true but capability string missing")
	}
	if !probed.LSMAttach && saw["bpf-lsm-attach"] {
		t.Error("LSMAttach probed false but capability string present")
	}
	if !probed.CgroupSock && saw["bpf-cgroup-sock"] {
		t.Error("CgroupSock probed false but capability string present")
	}
	if !probed.Tracepoint && saw["bpf-tracepoint"] {
		t.Error("Tracepoint probed false but capability string present")
	}
	if !probed.Ringbuf && saw["bpf-ringbuf"] {
		t.Error("Ringbuf probed false but capability string present")
	}
	// Keep the bpf import live on macOS, where every probed field is false
	// and none of the conditional branches above reference the package.
	_ = bpf.Capabilities{}
}

// TestConnectionTrackerCapabilityWhenBPFActive asserts the per-feature
// "bpf-connection-tracker" string appears iff the connection_tracker
// backend has been set to BPF.
func TestConnectionTrackerCapabilityWhenBPFActive(t *testing.T) {
	bpf.SetActive("connection_tracker", bpf.BackendBPF)
	if !contains(Capabilities(), "bpf-connection-tracker") {
		t.Error("bpf-connection-tracker missing when backend is BPF")
	}

	bpf.SetActive("connection_tracker", bpf.BackendLegacy)
	if contains(Capabilities(), "bpf-connection-tracker") {
		t.Error("bpf-connection-tracker present when backend is legacy")
	}

	bpf.SetActive("connection_tracker", bpf.BackendNone)
	if contains(Capabilities(), "bpf-connection-tracker") {
		t.Error("bpf-connection-tracker present when backend is none")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
