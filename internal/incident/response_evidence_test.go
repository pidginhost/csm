package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestCorrelatorIgnoresAutoBlockEvidence(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{
		Check: "auto_block", Message: "AUTO-BLOCK: 203.0.113.7 blocked",
		Severity: alert.Critical, SourceIP: "203.0.113.7",
		Timestamp: time.Unix(1_700_000_000, 0),
	}

	id, created, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if created || id != "" {
		t.Fatalf("auto-block evidence created incident id=%q created=%v", id, created)
	}
	if c.OpenCount() != 0 || c.PendingCount() != 0 {
		t.Fatalf("auto-block evidence changed correlator state: open=%d pending=%d", c.OpenCount(), c.PendingCount())
	}
}
