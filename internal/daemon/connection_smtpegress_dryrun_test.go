package daemon

import (
	"net"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestDirectSMTPEgressDryRunStillEmitsInPhase3(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	dr := true
	cfg.Detection.DirectSMTPEgress.DryRun = &dr // explicitly true (default anyway)

	mta := platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})
	ev := ConnectionEvent{
		UID: 1001, PID: 4242, Family: 2, DstPort: 587,
		DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat",
	}
	got := evaluateConnectionEvent(cfg, mta, ev, "alice")
	if len(got) == 0 {
		t.Errorf("Phase 3 detection must emit even when DryRun=true (gating is Phase 4)")
	}
}
