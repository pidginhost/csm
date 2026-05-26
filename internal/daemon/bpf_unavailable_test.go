package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
)

func TestEmitBPFUnavailableFinding_HighWhenOperatorRequestedBPF(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	if !emitBPFUnavailableFinding(ch, "connection_tracker", bpf.BackendBPF, "", errors.New("kernel < 5.7")) {
		t.Fatal("emit returned false on writable channel")
	}
	f := <-ch
	if f.Severity != alert.High {
		t.Errorf("Severity = %v, want High (operator asked for BPF explicitly)", f.Severity)
	}
	if f.Check != "bpf_unavailable" {
		t.Errorf("Check = %q, want bpf_unavailable", f.Check)
	}
	if !strings.Contains(f.Message, "no live fallback active") {
		t.Errorf("Message = %q, want no live fallback active", f.Message)
	}
}

func TestEmitBPFUnavailableFinding_WarningWhenChoiceIsAuto(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	emitBPFUnavailableFinding(ch, "exec_monitor", bpf.BackendAuto, bpf.BackendLegacy, errors.New("not built"))
	f := <-ch
	if f.Severity != alert.Warning {
		t.Errorf("Severity = %v, want Warning (auto choice fell back)", f.Severity)
	}
	if !strings.Contains(f.Message, "running on legacy fallback") {
		t.Errorf("Message = %q, want legacy fallback", f.Message)
	}
}

func TestEmitBPFUnavailableFinding_HighWhenNoFallbackActive(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	emitBPFUnavailableFinding(ch, "af_alg", bpf.BackendAuto, "", errors.New("audit log missing"))
	f := <-ch
	if f.Severity != alert.High {
		t.Errorf("Severity = %v, want High when no live fallback is active", f.Severity)
	}
}

func TestEmitBPFUnavailableFinding_NonBlockingOnFullChannel(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	ch <- alert.Finding{Check: "decoy"}
	if emitBPFUnavailableFinding(ch, "x", "auto", bpf.BackendLegacy, errors.New("x")) {
		t.Fatal("emit should fail-silent on full channel, not block")
	}
}
