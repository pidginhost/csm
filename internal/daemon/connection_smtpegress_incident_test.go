package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/platform"
)

// TestDirectSMTPEgressFindingFeedsIncidentCorrelator pins that a
// Phase 3 direct_smtp_egress finding, when routed through the
// correlator the way daemon.dispatchBatch does in production, lands
// as an incident with the right account attribution and kind.
//
// This calls Correlator.OnFinding directly, mirroring how
// internal/daemon/daemon.go dispatchBatch wires findings into the
// correlator (no observer fan-out is involved in production today).
func TestDirectSMTPEgressFindingFeedsIncidentCorrelator(t *testing.T) {
	resetIncidentForTest()
	c := IncidentCorrelator()

	f := alert.Finding{
		Severity:  alert.High,
		Check:     "direct_smtp_egress",
		Message:   "Non-MTA process opened outbound SMTP connection to 203.0.113.10:587",
		TenantID:  "alice",
		Timestamp: time.Now(),
	}
	id, created, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if !created {
		t.Errorf("expected incident creation; got merge")
	}
	if id == "" {
		t.Errorf("expected non-empty incident id")
	}
	if c.OpenCount() != 1 {
		t.Errorf("OpenCount: want 1, got %d", c.OpenCount())
	}

	snap := c.Snapshot()
	if len(snap) == 0 {
		t.Fatal("Snapshot empty")
	}
	if snap[0].Account != "alice" {
		t.Errorf("account: want alice, got %q", snap[0].Account)
	}
	// Default classification for account-attributed findings is
	// web_account_compromise. If a future kind classifier rule maps
	// direct_smtp_egress to mailbox_takeover, update this assertion.
	if snap[0].Kind != incident.KindWebAccountCompromise {
		t.Errorf("expected web_account_compromise; got %v", snap[0].Kind)
	}
}

func TestDirectSMTPEgressEvaluatorFindingFeedsIncidentCorrelator(t *testing.T) {
	resetIncidentForTest()
	installDirectSMTPRDNSCacheForTest(t, checks.NewRDNSCache(checks.RDNSCacheConfig{
		TTL:     time.Minute,
		Resolve: func(ip net.IP) (string, error) { return "", nil },
	}))
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	mta := platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})
	ev := ConnectionEvent{
		UID: 1001, PID: 4242, Family: 2, DstPort: 587,
		DstIP: net.ParseIP("203.0.113.10").To4(), Comm: "ncat",
	}

	var finding alert.Finding
	for _, f := range evaluateConnectionEvent(cfg, mta, ev, "alice") {
		if f.Check == "direct_smtp_egress" {
			finding = f
			break
		}
	}
	if finding.Check == "" {
		t.Fatal("expected direct_smtp_egress finding")
	}
	if finding.TenantID != "alice" {
		t.Fatalf("direct SMTP finding TenantID = %q, want alice", finding.TenantID)
	}

	c := IncidentCorrelator()
	id, created, err := c.OnFinding(finding)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if !created || id == "" {
		t.Fatalf("expected new incident id, created=%v id=%q", created, id)
	}
	if c.OpenCount() != 1 {
		t.Fatalf("OpenCount: want 1, got %d", c.OpenCount())
	}
}
