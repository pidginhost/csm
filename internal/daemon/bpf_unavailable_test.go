package daemon

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
)

func TestEmitBPFUnavailableFinding_HighWhenOperatorRequestedBPF(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	if !emitBPFUnavailableFinding(ch, "connection_tracker", bpf.BackendBPF, errors.New("kernel < 5.7")) {
		t.Fatal("emit returned false on writable channel")
	}
	f := <-ch
	if f.Severity != alert.High {
		t.Errorf("Severity = %v, want High (operator asked for BPF explicitly)", f.Severity)
	}
	if f.Check != "bpf_unavailable" {
		t.Errorf("Check = %q, want bpf_unavailable", f.Check)
	}
}

func TestEmitBPFUnavailableFinding_WarningWhenChoiceIsAuto(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	emitBPFUnavailableFinding(ch, "exec_monitor", bpf.BackendAuto, errors.New("not built"))
	f := <-ch
	if f.Severity != alert.Warning {
		t.Errorf("Severity = %v, want Warning (auto choice fell back)", f.Severity)
	}
}

func TestEmitBPFUnavailableFinding_NonBlockingOnFullChannel(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	ch <- alert.Finding{Check: "decoy"}
	if emitBPFUnavailableFinding(ch, "x", "auto", errors.New("x")) {
		t.Fatal("emit should fail-silent on full channel, not block")
	}
}
