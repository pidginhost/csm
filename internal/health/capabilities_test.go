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

func TestIncidentCapabilityAlwaysPresent(t *testing.T) {
	if !contains(Capabilities(), "incidents.v1") {
		t.Error("incidents.v1 capability missing")
	}
}

func TestBPFEnforcementAvailableCapabilityAlwaysPresent(t *testing.T) {
	if !contains(Capabilities(), "bpf_enforcement.available.v1") {
		t.Error("bpf_enforcement.available.v1 capability missing")
	}
}

func TestPrefsAndUndoCapabilitiesAlwaysPresent(t *testing.T) {
	caps := Capabilities()
	for _, want := range []string{"webui.prefs.v1", "webui.undo.v1"} {
		if !contains(caps, want) {
			t.Errorf("%s capability missing", want)
		}
	}
}

func TestMailVisibilityCapabilitiesAlwaysPresent(t *testing.T) {
	caps := Capabilities()
	for _, want := range []string{"mail.filter.exfil.v1", "mail.queue.composition.v1"} {
		if !contains(caps, want) {
			t.Errorf("%s capability missing", want)
		}
	}
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

func TestAFAlgCapabilityWhenBPFActive(t *testing.T) {
	bpf.SetActive("af_alg", bpf.BackendBPF)
	if !contains(Capabilities(), "bpf-af-alg-live") {
		t.Error("bpf-af-alg-live missing when AF_ALG backend is BPF")
	}

	bpf.SetActive("af_alg", bpf.BackendLegacy)
	if contains(Capabilities(), "bpf-af-alg-live") {
		t.Error("bpf-af-alg-live present when AF_ALG backend is legacy")
	}

	bpf.SetActive("af_alg", bpf.BackendNone)
	if contains(Capabilities(), "bpf-af-alg-live") {
		t.Error("bpf-af-alg-live present when AF_ALG backend is none")
	}
}

func TestExecMonitorCapabilityWhenBPFActive(t *testing.T) {
	bpf.SetActive("exec_monitor", bpf.BackendBPF)
	if !contains(Capabilities(), "bpf-exec-monitor") {
		t.Error("bpf-exec-monitor missing when exec backend is BPF")
	}

	bpf.SetActive("exec_monitor", bpf.BackendLegacy)
	if contains(Capabilities(), "bpf-exec-monitor") {
		t.Error("bpf-exec-monitor present when exec backend is legacy")
	}

	bpf.SetActive("exec_monitor", bpf.BackendNone)
	if contains(Capabilities(), "bpf-exec-monitor") {
		t.Error("bpf-exec-monitor present when exec backend is none")
	}
}

func TestSensitiveFilesCapabilityWhenBPFActive(t *testing.T) {
	bpf.SetActive("sensitive_files", bpf.BackendBPF)
	if !contains(Capabilities(), "bpf-sensitive-files") {
		t.Error("bpf-sensitive-files missing when sensitive_files backend is BPF")
	}

	bpf.SetActive("sensitive_files", bpf.BackendLegacy)
	if contains(Capabilities(), "bpf-sensitive-files") {
		t.Error("bpf-sensitive-files present when sensitive_files backend is legacy")
	}

	bpf.SetActive("sensitive_files", bpf.BackendNone)
	if contains(Capabilities(), "bpf-sensitive-files") {
		t.Error("bpf-sensitive-files present when sensitive_files backend is none")
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
