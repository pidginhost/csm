package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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
	c.OnFinding(f1)

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
