package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestIncidentCorrelatorSingletonReturnsSameInstance(t *testing.T) {
	resetIncidentForTest()
	c1 := IncidentCorrelator()
	c2 := IncidentCorrelator()
	if c1 != c2 {
		t.Fatal("expected singleton")
	}
}

func TestIncidentCorrelatorReceivesFindings(t *testing.T) {
	resetIncidentForTest()
	c := IncidentCorrelator()

	// Register the daemon's observer wiring.
	cancel := wireIncidentObserver(c)
	defer cancel()

	alert.EmitForTest(alert.Finding{
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

func TestIncidentCorrelatorSingletonIsIdempotent(t *testing.T) {
	resetIncidentForTest()
	_ = IncidentCorrelator()
	_ = IncidentCorrelator()
	_ = IncidentCorrelator()
	// No panic, no duplicate metric registration. The metrics seam is
	// pinned in TestMain to a private NewRegistry; if this test ever
	// hits metrics.Default it will panic on duplicate registration.
}
