package incident

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A credential-spray incident blocks only an address that a finding with
// address evidence attests, like every other incident block. Raw mailbox
// failures (the default per-check list) are visibility, not evidence.
func TestSprayBlockNeedsAnAttestedAddress(t *testing.T) {
	for _, c := range []struct {
		name, check string
		want        int
	}{
		{"failures without evidence", "email_auth_failure_realtime", 0},
		{"address evidence", "pam_bruteforce", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			var cap blockCapture
			corr := NewCorrelator(CorrelatorConfig{
				OpenThreshold: 1,
				SpraySuppression: SpraySuppressionConfig{
					Enabled:            true,
					DistinctMailboxes:  2,
					SeverityEscalateAt: 2,
					PerCheck:           map[string]bool{c.check: true},
					BlockAtSeverity:    "high",
				},
				OnSprayBlock:    cap.record,
				AddressEvidence: func(check string, _ alert.Severity) bool { return check == "pam_bruteforce" },
			})
			now := time.Unix(1_700_000_000, 0)
			corr.now = func() time.Time { return now }
			corr.spray.now = corr.now
			for i := 0; i < 3; i++ {
				f := alert.Finding{Check: c.check, Severity: alert.High, SourceIP: "192.0.2.76",
					Mailbox: fmt.Sprintf("user%d@example.com", i), Message: "failure", Timestamp: now}
				if _, _, err := corr.OnFinding(f); err != nil {
					t.Fatal(err)
				}
				now = now.Add(time.Second)
			}
			if got := cap.len(); got != c.want {
				t.Fatalf("spray blocks %d, want %d", got, c.want)
			}
		})
	}
}
