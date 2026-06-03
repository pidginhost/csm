package incident

import (
	"testing"
	"time"
)

// CloseStaleByAge is the kind-agnostic safety cap. It must force-close any
// Open/Contained incident older than maxAge regardless of whether the
// operator configured a per-kind auto-close threshold for that kind --
// otherwise incidents accumulate without bound when auto-close is off or a
// kind is omitted from the threshold map.
func TestCloseStaleByAgeClosesAnyOldActiveIncidentRegardlessOfKind(t *testing.T) {
	c := newTestCorrelator()
	old := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return old }

	// Three distinct kinds, none of which has any auto-close threshold here.
	for i, kind := range []string{"email_auth_failure_realtime", "wp_login_bruteforce", "ssh_bruteforce"} {
		seedIncident(t, c, kind, "user"+string(rune('a'+i)), old)
	}

	now := old.Add(40 * 24 * time.Hour)
	closed, more := c.CloseStaleByAge(now, 30*24*time.Hour, 0)
	if closed != 3 || more {
		t.Fatalf("age cap = (closed=%d more=%v), want (3,false)", closed, more)
	}
	for _, inc := range c.Snapshot() {
		if incidentStatusActive(inc.Status) {
			t.Fatalf("incident %s still active after age cap", inc.ID)
		}
		if inc.ClosedBy != "auto:age_cap" {
			t.Errorf("incident %s ClosedBy = %q, want auto:age_cap", inc.ID, inc.ClosedBy)
		}
	}

	// A young incident must survive the same sweep. The correlator stamps
	// UpdatedAt from its own clock, so advance it before seeding.
	c.now = func() time.Time { return now }
	young := seedIncident(t, c, "email_auth_failure_realtime", "fresh", now)
	closed2, _ := c.CloseStaleByAge(now.Add(time.Hour), 30*24*time.Hour, 0)
	if closed2 != 0 {
		t.Fatalf("young incident closed by age cap: closed=%d", closed2)
	}
	if got, ok := c.Get(young); !ok || !incidentStatusActive(got.Status) {
		t.Fatal("young incident should still be active")
	}
}

// EnforceActiveCap bounds the number of in-memory Open/Contained incidents,
// force-closing the oldest first when the count exceeds the cap.
func TestEnforceActiveCapClosesOldestOverCap(t *testing.T) {
	c := newTestCorrelator()
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }

	// Five active incidents, each one hour older than the next.
	ids := make([]string, 5)
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i) * time.Hour)
		c.now = func() time.Time { return ts }
		ids[i] = seedIncident(t, c, "email_auth_failure_realtime", "u"+string(rune('a'+i)), ts)
	}

	now := base.Add(10 * time.Hour)
	closed, more := c.EnforceActiveCap(now, 3, 0)
	if closed != 2 || more {
		t.Fatalf("active cap = (closed=%d more=%v), want (2,false)", closed, more)
	}

	// The two oldest (ids[0], ids[1]) must be closed; the rest active.
	for i, id := range ids {
		inc, ok := c.Get(id)
		if !ok {
			t.Fatalf("incident %s missing", id)
		}
		wantActive := i >= 2
		if incidentStatusActive(inc.Status) != wantActive {
			t.Errorf("incident %d (%s) active=%v, want %v", i, id, incidentStatusActive(inc.Status), wantActive)
		}
	}

	// Already at cap: no-op.
	closed2, _ := c.EnforceActiveCap(now, 3, 0)
	if closed2 != 0 {
		t.Fatalf("second sweep closed %d, want 0 (already at cap)", closed2)
	}
}
