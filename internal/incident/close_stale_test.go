package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// seedIncident plants a single attributable finding so the correlator
// has an Open incident to age. Threshold pinned to 1 (resetIncidentForTest
// does this in production code; for unit tests we just call OnFinding once).
func seedIncident(t *testing.T, c *Correlator, kind string, mailbox string, ts time.Time) string {
	t.Helper()
	c.openThreshold = 1
	id, _, err := c.OnFinding(alert.Finding{
		Check:     kind,
		Message:   "seed",
		Severity:  alert.High,
		Mailbox:   mailbox,
		Timestamp: ts,
	})
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if id == "" {
		t.Fatalf("expected incident id; correlator dropped seed finding")
	}
	return id
}

func TestCloseStaleClosesIncidentsOlderThanThreshold(t *testing.T) {
	c := newTestCorrelator()
	old := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return old }
	id := seedIncident(t, c, "email_auth_failure_realtime", "jane", old)

	// Verify it is open before the close pass.
	inc, ok := c.Get(id)
	if !ok || inc.Status != StatusOpen {
		t.Fatalf("expected new incident open, got %+v", inc)
	}

	// Run CloseStale 25h later with a 24h threshold for mailbox_takeover.
	// email_auth_failure_realtime classifies as mailbox_takeover (kind.go).
	now := old.Add(25 * time.Hour)
	closed, dryRun, scanned := c.CloseStale(now,
		map[Kind]time.Duration{KindMailboxTakeover: 24 * time.Hour}, false)
	if closed != 1 || dryRun != 0 || scanned != 1 {
		t.Errorf("CloseStale = (closed=%d dryRun=%d scanned=%d), want (1,0,1)", closed, dryRun, scanned)
	}

	got, _ := c.Get(id)
	if got.Status != StatusResolved {
		t.Errorf("status = %s, want resolved", got.Status)
	}
	if got.ClosedBy != "auto:stale" {
		t.Errorf("closed_by = %q, want auto:stale", got.ClosedBy)
	}
	if got.ClosedAt.IsZero() {
		t.Error("closed_at must be set on auto-close")
	}
	// Last action must reflect the auto-close decision.
	if n := len(got.Actions); n == 0 || got.Actions[n-1].Action != "incident_auto_closed" {
		t.Errorf("expected trailing incident_auto_closed action, got %+v", got.Actions)
	}
}

func TestCloseStaleSkipsIncidentsWithinWindow(t *testing.T) {
	c := newTestCorrelator()
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	id := seedIncident(t, c, "email_auth_failure_realtime", "fresh", now)

	// 1 hour later: well inside the 24h threshold.
	closed, _, scanned := c.CloseStale(now.Add(1*time.Hour),
		map[Kind]time.Duration{KindMailboxTakeover: 24 * time.Hour}, false)
	if closed != 0 || scanned != 0 {
		t.Errorf("CloseStale closed=%d scanned=%d, want (0,0)", closed, scanned)
	}
	got, _ := c.Get(id)
	if got.Status != StatusOpen {
		t.Errorf("status = %s, want open", got.Status)
	}
}

func TestCloseStaleSkipsKindsWithoutThreshold(t *testing.T) {
	c := newTestCorrelator()
	old := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return old }
	// HostIntegrityRisk is intentionally absent from the threshold map so
	// verdict-emitted kinds never auto-close.
	id, _, err := c.OnFinding(alert.Finding{
		Check:     "sensitive_file_write",
		Message:   "tamper",
		Severity:  alert.Critical,
		TenantID:  "root",
		Timestamp: old,
	})
	if err != nil || id == "" {
		t.Fatalf("seed: id=%q err=%v", id, err)
	}

	closed, _, scanned := c.CloseStale(old.Add(48*time.Hour),
		map[Kind]time.Duration{KindMailboxTakeover: 24 * time.Hour}, false)
	if closed != 0 || scanned != 0 {
		t.Errorf("kind without threshold must not be touched (closed=%d scanned=%d)", closed, scanned)
	}
	got, _ := c.Get(id)
	if got.Status != StatusOpen {
		t.Errorf("status = %s, want open (host integrity must stay open)", got.Status)
	}
}

func TestCloseStaleHonorsDryRun(t *testing.T) {
	c := newTestCorrelator()
	old := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return old }
	id := seedIncident(t, c, "email_auth_failure_realtime", "jane", old)

	closed, dryRun, scanned := c.CloseStale(old.Add(48*time.Hour),
		map[Kind]time.Duration{KindMailboxTakeover: 24 * time.Hour}, true)
	if closed != 0 {
		t.Errorf("dry_run must not flip status (closed=%d)", closed)
	}
	if dryRun != 1 || scanned != 1 {
		t.Errorf("dry_run accounting wrong: dryRun=%d scanned=%d, want (1,1)", dryRun, scanned)
	}
	got, _ := c.Get(id)
	if got.Status != StatusOpen {
		t.Errorf("status = %s, want open under dry_run", got.Status)
	}
	if got.ClosedAt.IsZero() == false {
		t.Error("closed_at must remain zero in dry_run")
	}
	if c.counters.autoClosedTotal.Load() != 0 {
		t.Errorf("autoClosedTotal must stay 0 in dry_run, got %d", c.counters.autoClosedTotal.Load())
	}
	if c.counters.autoCloseDryRunTotal.Load() != 1 {
		t.Errorf("autoCloseDryRunTotal = %d, want 1", c.counters.autoCloseDryRunTotal.Load())
	}
}

func TestCloseStalePersistsClosedReason(t *testing.T) {
	var persisted []Incident
	c := NewCorrelator(CorrelatorConfig{
		Persist: func(snap Incident) { persisted = append(persisted, snap) },
	})
	old := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return old }
	c.openThreshold = 1
	_, _, err := c.OnFinding(alert.Finding{
		Check: "email_auth_failure_realtime", Severity: alert.High,
		Mailbox: "jane", Timestamp: old, Message: "seed",
	})
	if err != nil {
		t.Fatal(err)
	}

	persisted = nil // reset; only inspect the close write
	now := old.Add(25 * time.Hour)
	c.CloseStale(now, map[Kind]time.Duration{KindMailboxTakeover: 24 * time.Hour}, false)
	if len(persisted) != 1 {
		t.Fatalf("Persist invoked %d times, want 1 close", len(persisted))
	}
	closed := persisted[0]
	if closed.Status != StatusResolved || closed.ClosedBy != "auto:stale" || closed.ClosedAt.IsZero() {
		t.Errorf("persisted close incomplete: %+v", closed)
	}
}

func TestStaleResolvedIncidentLetsKeyOpenNewIncident(t *testing.T) {
	// Regression: after CloseStale resolves the bound incident for a key,
	// a fresh finding for the same key must produce a new open incident.
	c := newTestCorrelator()
	old := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return old }
	first := seedIncident(t, c, "email_auth_failure_realtime", "jane", old)

	close25h := old.Add(25 * time.Hour)
	c.CloseStale(close25h, map[Kind]time.Duration{KindMailboxTakeover: 24 * time.Hour}, false)
	if got, _ := c.Get(first); got.Status != StatusResolved {
		t.Fatalf("setup: expected first incident resolved, got %s", got.Status)
	}

	// 30 minutes later attacker hits jane again. correlator.now drives the
	// merge-window timestamps inside OnFinding.
	c.now = func() time.Time { return close25h.Add(30 * time.Minute) }
	c.openThreshold = 1
	id2, created, err := c.OnFinding(alert.Finding{
		Check:     "email_auth_failure_realtime",
		Severity:  alert.High,
		Mailbox:   "jane",
		Timestamp: close25h.Add(30 * time.Minute),
		Message:   "second wave",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Errorf("expected fresh incident after stale close, got created=%v id=%q", created, id2)
	}
	if id2 == first {
		t.Errorf("new incident must have a different id from the closed one")
	}
	got, _ := c.Get(id2)
	if got.Status != StatusOpen {
		t.Errorf("new incident status = %s, want open", got.Status)
	}
}

func TestCloseStaleEmptyThresholdMapIsNoOp(t *testing.T) {
	c := newTestCorrelator()
	old := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return old }
	seedIncident(t, c, "email_auth_failure_realtime", "jane", old)
	closed, dryRun, scanned := c.CloseStale(old.Add(48*time.Hour), nil, false)
	if closed != 0 || dryRun != 0 || scanned != 0 {
		t.Errorf("nil thresholds must short-circuit (closed=%d dryRun=%d scanned=%d)", closed, dryRun, scanned)
	}
}

func TestCloseStaleSkipsAlreadyResolved(t *testing.T) {
	// Re-running CloseStale on the same incident twice must close it once
	// and then no-op. This is what the hourly daemon ticker actually does.
	c := newTestCorrelator()
	old := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return old }
	seedIncident(t, c, "email_auth_failure_realtime", "jane", old)

	now := old.Add(25 * time.Hour)
	closed1, _, _ := c.CloseStale(now, map[Kind]time.Duration{KindMailboxTakeover: 24 * time.Hour}, false)
	closed2, _, _ := c.CloseStale(now.Add(time.Hour), map[Kind]time.Duration{KindMailboxTakeover: 24 * time.Hour}, false)
	if closed1 != 1 || closed2 != 0 {
		t.Errorf("repeat close: first=%d second=%d, want (1,0)", closed1, closed2)
	}
}
