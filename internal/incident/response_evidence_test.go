package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestCorrelatorIgnoresResponseAndHealthEvidence(t *testing.T) {
	for _, check := range []string{"auto_block", "reputation_quota_exhausted", "threat_feed_stale"} {
		t.Run(check, func(t *testing.T) {
			c := newTestCorrelator()
			f := alert.Finding{
				Check: check, Message: "response or coverage evidence",
				Severity: alert.Critical, SourceIP: "203.0.113.7",
				Timestamp: time.Unix(1_700_000_000, 0),
			}

			id, created, err := c.OnFinding(f)
			if err != nil {
				t.Fatalf("OnFinding: %v", err)
			}
			if created || id != "" {
				t.Fatalf("%s evidence created incident id=%q created=%v", check, id, created)
			}
			if c.OpenCount() != 0 || c.PendingCount() != 0 {
				t.Fatalf("%s evidence changed correlator state: open=%d pending=%d", check, c.OpenCount(), c.PendingCount())
			}
		})
	}
}
