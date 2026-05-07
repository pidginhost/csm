package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

func newTestCorrelator() *Correlator {
	c := NewCorrelator(CorrelatorConfig{})
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return c
}

func TestCorrelatorOnFindingCreatesIncidentForAttributableFinding(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{
		Check:     "wp_login_bruteforce",
		Message:   "burst",
		Severity:  alert.High,
		TenantID:  "alice",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id, created, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if !created {
		t.Errorf("expected first call to create an incident")
	}
	if id == "" {
		t.Errorf("expected non-empty incident id")
	}
}

func TestCorrelatorOnFindingReturnsZeroForUnattributable(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{Check: "system_load", Message: "system load high", Timestamp: time.Unix(1_700_000_000, 0)}
	id, created, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if created {
		t.Errorf("unattributable finding must not create incident")
	}
	if id != "" {
		t.Errorf("expected empty id, got %q", id)
	}
}

func TestCorrelatorMergesSameAccountInWindow(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{Check: "wp_login_bruteforce", Message: "1", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	id1, created1, _ := c.OnFinding(f1)
	if !created1 {
		t.Fatal("setup")
	}

	c.now = func() time.Time { return time.Unix(1_700_000_000+5*60, 0) }
	f2 := alert.Finding{Check: "outbound_connection", Message: "2", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+5*60, 0)}
	id2, created2, _ := c.OnFinding(f2)

	if created2 {
		t.Errorf("second finding within window must merge, not create")
	}
	if id1 != id2 {
		t.Errorf("ids must match: %q vs %q", id1, id2)
	}
}

func TestCorrelatorDoesNotMergeAcrossAccounts(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	id1, _, _ := c.OnFinding(f1)

	f2 := alert.Finding{Check: "x", Severity: alert.High, TenantID: "bob", Timestamp: time.Unix(1_700_000_000, 0)}
	id2, created2, _ := c.OnFinding(f2)

	if !created2 {
		t.Errorf("different account must create new incident")
	}
	if id1 == id2 {
		t.Errorf("ids must differ across accounts")
	}
}

func TestCorrelatorDoesNotMergeOutsideWindow(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	_, _, _ = c.OnFinding(f1)

	c.now = func() time.Time { return time.Unix(1_700_000_000+16*60, 0) }
	f2 := alert.Finding{Check: "y", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+16*60, 0)}
	_, created2, _ := c.OnFinding(f2)

	if !created2 {
		t.Errorf("finding 16 min later must create new incident (window is 15 min)")
	}
}

func TestCorrelatorAppendsTimeline(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{Check: "wp_login_bruteforce", Message: "first", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	id, _, _ := c.OnFinding(f)

	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("incident not found by id")
	}
	if len(inc.Timeline) != 1 {
		t.Fatalf("Timeline len: want 1, got %d", len(inc.Timeline))
	}
	if inc.Timeline[0].Check != "wp_login_bruteforce" {
		t.Errorf("Timeline[0].Check: %q", inc.Timeline[0].Check)
	}
}

func TestCorrelatorProcessOnlyFindingsDoNotCollide(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{
		Check:     "outbound_connection",
		Severity:  alert.High,
		Process:   &processctx.ProcessContext{PID: 4242, UID: 1001},
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id1, created1, _ := c.OnFinding(f1)
	if !created1 {
		t.Fatal("setup")
	}

	f2 := alert.Finding{
		Check:     "outbound_connection",
		Severity:  alert.High,
		Process:   &processctx.ProcessContext{PID: 5555, UID: 1002},
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id2, created2, _ := c.OnFinding(f2)
	if !created2 {
		t.Errorf("distinct process must produce a new incident, not merge")
	}
	if id1 == id2 {
		t.Errorf("process-only ids must differ")
	}
}

func TestCorrelatorRemoteIPOnlyFindingsDoNotCollide(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{
		Check:     "ssh_bruteforce",
		Severity:  alert.High,
		SourceIP:  "203.0.113.10",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id1, _, _ := c.OnFinding(f1)
	f2 := alert.Finding{
		Check:     "ssh_bruteforce",
		Severity:  alert.High,
		SourceIP:  "203.0.113.20",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id2, created2, _ := c.OnFinding(f2)
	if !created2 || id1 == id2 {
		t.Errorf("distinct remote IPs must not merge; id1=%s id2=%s created2=%v", id1, id2, created2)
	}
}

func TestCorrelatorPersistFiresExactlyOncePerCreateAndMerge(t *testing.T) {
	var calls int
	c := NewCorrelator(CorrelatorConfig{
		Persist: func(_ Incident) { calls++ },
	})
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)})
	if calls != 1 {
		t.Errorf("after create: want 1 Persist call, got %d", calls)
	}

	c.OnFinding(alert.Finding{Check: "y", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)})
	if calls != 2 {
		t.Errorf("after merge: want 2 Persist calls total, got %d", calls)
	}
}

func TestCorrelatorIncidentSeverityEscalates(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.Warning, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	id, _, _ := c.OnFinding(f1)
	f2 := alert.Finding{Check: "outbound_connection", Severity: alert.Critical, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+30, 0)}
	c.OnFinding(f2)

	inc, _ := c.Get(id)
	if inc.Severity != alert.Critical {
		t.Errorf("Incident severity: want Critical, got %v", inc.Severity)
	}
}

func TestCorrelatorEscalationAppendsAction(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{Check: "x", Severity: alert.Warning, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	id, _, _ := c.OnFinding(f1)
	f2 := alert.Finding{Check: "y", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+30, 0)}
	c.OnFinding(f2)

	inc, _ := c.Get(id)
	if len(inc.Actions) != 1 {
		t.Fatalf("Actions len: want 1 escalation action, got %d", len(inc.Actions))
	}
	if inc.Actions[0].Action != "incident_severity_changed" {
		t.Errorf("Action: %q", inc.Actions[0].Action)
	}
}

func TestCorrelatorDoesNotDowngradeSeverity(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{Check: "x", Severity: alert.Critical, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	id, _, _ := c.OnFinding(f1)
	f2 := alert.Finding{Check: "y", Severity: alert.Warning, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+30, 0)}
	c.OnFinding(f2)

	inc, _ := c.Get(id)
	if inc.Severity != alert.Critical {
		t.Errorf("Severity must not downgrade: got %v", inc.Severity)
	}
	if len(inc.Actions) != 0 {
		t.Errorf("No-downgrade must not append action; got %d", len(inc.Actions))
	}
}

func TestCorrelatorPersistRunsOutsideLock(t *testing.T) {
	// A Persist callback that re-enters Correlator must not deadlock.
	c := NewCorrelator(CorrelatorConfig{})
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	// Install Persist after construction so we have the *Correlator.
	c.cfg.Persist = func(inc Incident) {
		// Re-enter; if mu were held this would deadlock the test.
		_, _ = c.Get(inc.ID)
	}

	done := make(chan struct{})
	go func() {
		c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("OnFinding deadlocked under reentrant Persist")
	}
}

func TestCorrelatorRestoreRehydratesFromList(t *testing.T) {
	c := newTestCorrelator()
	prior := Incident{
		ID: "inc_resumed", Kind: KindWebAccountCompromise, Status: StatusOpen,
		Severity: alert.High, Account: "alice",
		CreatedAt: time.Unix(1_700_000_000, 0), UpdatedAt: time.Unix(1_700_000_000, 0),
	}
	c.Restore([]Incident{prior})

	c.now = func() time.Time { return time.Unix(1_700_000_000+5*60, 0) }
	id, created, _ := c.OnFinding(alert.Finding{
		Check: "x", Severity: alert.High, TenantID: "alice",
		Timestamp: time.Unix(1_700_000_000+5*60, 0),
	})
	if created {
		t.Errorf("post-restart finding for same account in window must merge, not create")
	}
	if id != "inc_resumed" {
		t.Errorf("expected merge into restored incident; got %q", id)
	}
}

func TestCorrelatorRestoreSkipsClosedIncidents(t *testing.T) {
	c := newTestCorrelator()
	resolved := Incident{
		ID: "inc_closed", Status: StatusResolved, Severity: alert.High, Account: "alice",
		CreatedAt: time.Unix(1_700_000_000, 0), UpdatedAt: time.Unix(1_700_000_000, 0),
	}
	c.Restore([]Incident{resolved})

	c.now = func() time.Time { return time.Unix(1_700_000_000+5*60, 0) }
	_, created, _ := c.OnFinding(alert.Finding{
		Check: "x", Severity: alert.High, TenantID: "alice",
		Timestamp: time.Unix(1_700_000_000+5*60, 0),
	})
	if !created {
		t.Errorf("Restore must NOT bind closed incidents to the active byKey index")
	}
}

func TestCorrelatorSetStatusUpdatesIncidentAndAppendsAction(t *testing.T) {
	c := newTestCorrelator()
	id, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)})

	if err := c.SetStatus(id, StatusResolved, "operator-marked"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	inc, _ := c.Get(id)
	if inc.Status != StatusResolved {
		t.Errorf("Status: %v", inc.Status)
	}
	if len(inc.Actions) == 0 {
		t.Fatal("expected status-change action")
	}
	last := inc.Actions[len(inc.Actions)-1]
	if last.Action != "incident_status_changed" {
		t.Errorf("Action: %q", last.Action)
	}
}

func TestCorrelatorSetStatusUnbindsClosed(t *testing.T) {
	c := newTestCorrelator()
	id1, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)})
	if err := c.SetStatus(id1, StatusResolved, "done"); err != nil {
		t.Fatal(err)
	}

	c.now = func() time.Time { return time.Unix(1_700_000_000+30, 0) }
	id2, created, _ := c.OnFinding(alert.Finding{Check: "y", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+30, 0)})
	if !created {
		t.Errorf("after status=resolved, the next finding for the account must start a new incident")
	}
	if id1 == id2 {
		t.Errorf("ids must differ; got %q twice", id1)
	}
}

func TestCorrelatorSetStatusRejectsUnknownID(t *testing.T) {
	c := newTestCorrelator()
	if err := c.SetStatus("inc_nope", StatusResolved, ""); err == nil {
		t.Errorf("expected error for unknown id")
	}
}
