package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
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
