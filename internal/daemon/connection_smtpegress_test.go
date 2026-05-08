package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestProcessConnectionEventEmitsDirectSMTPEgressFinding(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{25, 465, 587}
	mta := platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})

	ev := ConnectionEvent{
		UID:     1001,
		PID:     4242,
		Family:  2,
		DstPort: 587,
		DstIP:   net.ParseIP("203.0.113.10").To4(),
		Comm:    "ncat",
	}

	got := evaluateConnectionEvent(cfg, mta, ev, "alice")

	var sawEgress bool
	for _, f := range got {
		if f.Check == "direct_smtp_egress" {
			sawEgress = true
		}
	}
	if !sawEgress {
		t.Errorf("expected a direct_smtp_egress finding; got %+v", got)
	}
}

func TestProcessConnectionEventDoesNotDoubleEmitForSMTP(t *testing.T) {
	// EvaluateConnection skips SMTP destinations via safeRemotePorts;
	// only EvaluateDirectSMTPEgress should fire for an outbound 587.
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{25, 465, 587}
	mta := platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})

	ev := ConnectionEvent{
		UID: 1001, PID: 4242, Family: 2, DstPort: 587,
		DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat",
	}

	got := evaluateConnectionEvent(cfg, mta, ev, "alice")

	checkSet := map[string]int{}
	for _, f := range got {
		checkSet[f.Check]++
	}
	if checkSet["user_outbound_connection"] != 0 {
		t.Errorf("user_outbound_connection must not double-fire on SMTP destination; got %d", checkSet["user_outbound_connection"])
	}
}

func TestProcessConnectionEventTimestampSet(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	mta := platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})
	ev := ConnectionEvent{
		UID: 1001, PID: 4242, Family: 2, DstPort: 587,
		DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat",
	}
	got := evaluateConnectionEvent(cfg, mta, ev, "alice")
	if len(got) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range got {
		if f.Timestamp.IsZero() {
			t.Errorf("Timestamp must be set on emitted finding (%s)", f.Check)
		}
		if time.Since(f.Timestamp) > time.Second {
			t.Errorf("Timestamp too old: %v", f.Timestamp)
		}
	}
}
