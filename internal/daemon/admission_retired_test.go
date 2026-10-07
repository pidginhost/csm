package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/reporting"
)

// Retired session findings never corroborate a central response, with or
// without their stored database cause.
func TestCentralRejectsRetiredSessionAddressCorroboration(t *testing.T) {
	cfg, b := applyWiringSetup(t)
	d := New(cfg, nil, nil, "")
	store := centralStoreWith(t, []reporting.ScoredEntry{{IP: "198.51.100.22", Score: 95, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()}})
	for _, cause := range []*alert.Cause{nil, {Check: "db_siteurl_hijack", FindingID: "0123456789abcdef"}} {
		f := alert.Finding{Check: "local_threat_score", Severity: alert.Critical, SourceIP: "198.51.100.22", Cause: cause}
		if a, ok := d.planCentralAction(store, reporting.ActionBlockIfLocalCorroborated, 80, func(string) bool { return false }, f); ok {
			t.Fatalf("retired session selected central action %+v", a)
		}
	}
	if len(b.calls) != 0 {
		t.Fatalf("session addresses reached the firewall: %+v", b.calls)
	}
}
