package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/store"
)

func TestIncidentCorrelatorSingletonReturnsSameInstance(t *testing.T) {
	resetIncidentForTest()
	c1 := IncidentCorrelator()
	c2 := IncidentCorrelator()
	if c1 != c2 {
		t.Fatal("expected singleton")
	}
}

func TestIncidentCorrelatorIngestsDirectFindings(t *testing.T) {
	resetIncidentForTest()
	c := IncidentCorrelator()

	_, _, _ = c.OnFinding(alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.High,
		TenantID:  "alice",
		Timestamp: time.Now(),
	})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.OpenCount() > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("incident not created within deadline")
}

// TestIncidentCorrelatorHonorsProductionThreshold proves the daemon
// wires the production OpenThreshold (>= 2) through to the correlator
// singleton, so an isolated High-severity finding does NOT open an
// incident on the first hit. This is the wiring contract that keeps
// scanner one-shots out of the /incident page on busy hosts.
func TestIncidentCorrelatorHonorsProductionThreshold(t *testing.T) {
	resetIncidentForTestWithThreshold(2)
	c := IncidentCorrelator()

	f := alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.High,
		TenantID:  "alice",
		Timestamp: time.Now(),
	}
	if _, created, _ := c.OnFinding(f); created {
		t.Fatalf("first non-Critical finding opened incident under production threshold")
	}
	if got := c.OpenCount(); got != 0 {
		t.Fatalf("OpenCount after first finding = %d, want 0", got)
	}
	if got := c.PendingCount(); got != 1 {
		t.Fatalf("PendingCount after first finding = %d, want 1", got)
	}

	// Second correlated finding inside the merge window must promote.
	if _, created, _ := c.OnFinding(f); !created {
		t.Fatalf("second finding did not open incident")
	}
	if got := c.OpenCount(); got != 1 {
		t.Fatalf("OpenCount after second finding = %d, want 1", got)
	}
}

// TestIncidentCorrelatorCriticalBypassesThreshold proves Critical
// findings page on first hit even under the production threshold.
// Account-compromise events must not be deferred to a second event.
func TestIncidentCorrelatorCriticalBypassesThreshold(t *testing.T) {
	resetIncidentForTestWithThreshold(2)
	c := IncidentCorrelator()

	if _, created, _ := c.OnFinding(alert.Finding{
		Check:     "email_compromised_account",
		Severity:  alert.Critical,
		Mailbox:   "alice@example.com",
		Domain:    "example.com",
		Timestamp: time.Now(),
	}); !created {
		t.Fatalf("Critical finding did not open incident on first hit")
	}
	if got := c.OpenCount(); got != 1 {
		t.Fatalf("OpenCount = %d, want 1", got)
	}
}

func TestRunIncidentCompactionPrunesStoreAndMemory(t *testing.T) {
	resetIncidentForTest()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		resetIncidentForTest()
		store.SetGlobal(prev)
		_ = db.Close()
	})

	old := time.Now().Add(-(incidentRetentionPeriod + time.Hour))
	inc := incident.Incident{
		ID:        "inc_old",
		Status:    incident.StatusResolved,
		Severity:  alert.High,
		Account:   "alice",
		CreatedAt: old,
		UpdatedAt: old,
	}
	if err := db.SaveIncident(inc); err != nil {
		t.Fatalf("SaveIncident: %v", err)
	}

	c := IncidentCorrelator()
	if _, ok := c.Get("inc_old"); !ok {
		t.Fatal("setup incident was not restored into memory")
	}

	runIncidentCompaction(c)
	if _, ok := c.Get("inc_old"); ok {
		t.Fatal("compacted incident still visible in memory")
	}
	if _, ok, err := db.GetIncident("inc_old"); err != nil {
		t.Fatalf("GetIncident: %v", err)
	} else if ok {
		t.Fatal("compacted incident still visible in store")
	}
}

func TestIncidentCorrelatorSingletonIsIdempotent(t *testing.T) {
	resetIncidentForTest()
	_ = IncidentCorrelator()
	_ = IncidentCorrelator()
	_ = IncidentCorrelator()
	// No panic, no duplicate metric registration. The metrics seam is
	// pinned in TestMain to a private NewRegistry; if this test ever
	// hits metrics.Default it will panic on duplicate registration.
}
