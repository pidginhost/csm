package incident

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// sprayIncidentSeverity returns the severity of the single credential_spray
// incident, or an empty severity when none is open.
func sprayIncidentSeverity(c *Correlator) alert.Severity {
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			return inc.Severity
		}
	}
	return alert.Severity(0)
}

// TestMergeDebouncesBookkeepingPersists proves that a burst of merges that only
// append fingerprint/timeline bookkeeping (no severity/kind transition) does not
// rewrite the whole incident blob once per finding. Within the debounce window
// they collapse to the single create write.
func TestMergeDebouncesBookkeepingPersists(t *testing.T) {
	var calls int32
	c := NewCorrelator(CorrelatorConfig{
		Persist: func(Incident) { atomic.AddInt32(&calls, 1) },
	})
	c.openThreshold = 1
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }

	f := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.High, TenantID: "alice", Timestamp: base}
	if _, created, _ := c.OnFinding(f); !created {
		t.Fatal("first finding should open an incident")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("open should persist once, got %d", got)
	}

	for i := 0; i < 10; i++ {
		_, _, _ = c.OnFinding(f)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("bookkeeping merges within debounce window must not each rewrite the blob: got %d writes, want 1", got)
	}
}

// TestMergePersistsAfterDebounceWindow confirms the debounce is time-bounded:
// once the window elapses a fresh bookkeeping merge persists again, so at most
// one debounce window of fingerprint bookkeeping is ever at risk on a hard kill.
func TestMergePersistsAfterDebounceWindow(t *testing.T) {
	var calls int32
	c := NewCorrelator(CorrelatorConfig{
		Persist: func(Incident) { atomic.AddInt32(&calls, 1) },
	})
	c.openThreshold = 1
	base := time.Unix(1_700_000_000, 0)
	clock := base
	c.now = func() time.Time { return clock }

	f := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.High, TenantID: "alice", Timestamp: base}
	_, _, _ = c.OnFinding(f) // open, persist #1
	_, _, _ = c.OnFinding(f) // debounced, no write
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("within window: want 1 write, got %d", got)
	}

	clock = base.Add(incidentPersistDebounce + time.Second)
	_, _, _ = c.OnFinding(f) // window elapsed -> persists again
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("after window: want 2 writes, got %d", got)
	}
}

// TestSeverityEscalationPersistsWithinDebounceWindow proves a state-changing
// transition (severity escalation) always persists synchronously, even when it
// lands inside the debounce window of a prior write.
func TestSeverityEscalationPersistsWithinDebounceWindow(t *testing.T) {
	var calls int32
	c := NewCorrelator(CorrelatorConfig{
		Persist: func(Incident) { atomic.AddInt32(&calls, 1) },
	})
	c.openThreshold = 1
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }

	_, _, _ = c.OnFinding(alert.Finding{Check: "wp_login_bruteforce", Severity: alert.Warning, TenantID: "alice", Timestamp: base})
	before := atomic.LoadInt32(&calls)
	// Same key, same clock (inside debounce window), higher severity.
	_, _, _ = c.OnFinding(alert.Finding{Check: "outbound_connection", Severity: alert.Critical, TenantID: "alice", Timestamp: base})
	if got := atomic.LoadInt32(&calls); got != before+1 {
		t.Fatalf("severity escalation must persist synchronously within the debounce window: delta=%d, want 1", got-before)
	}
}

// TestSpraySuppressEscalationPersistsOnce is a regression for the double-persist
// in the credential_spray suppression path: the finding that escalates the
// super-incident to Critical must write exactly once, not twice.
func TestSpraySuppressEscalationPersistsOnce(t *testing.T) {
	var calls int32
	c := NewCorrelator(CorrelatorConfig{
		SpraySuppression: sprayTestConfig(true, false),
		Persist:          func(Incident) { atomic.AddInt32(&calls, 1) },
	})
	c.openThreshold = 1
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	if c.spray != nil {
		c.spray.now = c.now
	}
	c.spray.cfg.SeverityEscalateAt = 5

	escalationDelta := int32(-1)
	for i := 0; i < 8 && escalationDelta < 0; i++ {
		mb := "user" + strconv.Itoa(i) + "@example.com"
		before := atomic.LoadInt32(&calls)
		_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.1", base))
		after := atomic.LoadInt32(&calls)
		if sprayIncidentSeverity(c) == alert.Critical {
			escalationDelta = after - before
		}
	}
	if escalationDelta != 1 {
		t.Fatalf("spray escalation finding persisted %d times, want exactly 1 (no double-persist)", escalationDelta)
	}
}
