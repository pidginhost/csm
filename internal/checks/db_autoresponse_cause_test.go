package checks

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// The synthetic findings for WordPress session attackers name the database
// finding that caused them, as data the admission adapter reads; the public
// JSON is unchanged.
func TestSessionAttackerFindingsCarryTheirCause(t *testing.T) {
	cause := alert.Cause{FindingID: "0123456789abcdef", Check: "db_siteurl_hijack"}
	got := sessionAttackerFindings([]string{"203.0.113.7", "203.0.113.8"}, "active session on hijacked site, DB: db1", cause)
	if len(got) != 2 {
		t.Fatalf("findings %+v, want one per address", got)
	}
	for i, f := range got {
		if f.Check != "local_threat_score" || f.SourceIP != []string{"203.0.113.7", "203.0.113.8"}[i] || f.Cause == nil || *f.Cause != cause {
			t.Errorf("finding %d = %+v, want local_threat_score for its address caused by %+v", i, f, cause)
		}
	}
	if got[0].Cause == got[1].Cause {
		t.Fatal("findings share one cause value")
	}
	raw, err := json.Marshal(got[0])
	if err != nil || strings.Contains(string(raw), "db_siteurl_hijack") || strings.Contains(string(raw), `"cause"`) {
		t.Fatalf("public JSON %s (error %v) names the cause", raw, err)
	}
}
