package attackdb

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Raw mail login failures are visibility: a mistyped password, a stale phone
// behind an office NAT and a mail auth backend outage all produce them. The
// mail trackers decide blocking with their own success and outage gates, so
// these failures never build a threat score that could block on its own.
func TestRawMailAuthFailuresAddNoThreatScore(t *testing.T) {
	db := NewForTest(nil)
	now := time.Now()
	for i := 0; i < 120; i++ {
		db.RecordFinding(alert.Finding{
			Check:     "email_auth_failure_realtime",
			Severity:  alert.High,
			SourceIP:  "203.0.113.9",
			Mailbox:   fmt.Sprintf("user%d@example.com", i%3),
			Timestamp: now.Add(time.Duration(i) * 10 * time.Second),
		})
	}
	if rec := db.LookupIP("203.0.113.9"); rec != nil {
		t.Fatalf("raw mail auth failures built a threat record with score %d", ComputeScore(rec))
	}
}
