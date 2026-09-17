package attackdb

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestLoginUpgradePendingFindings(t *testing.T) {
	for check, want := range map[string]AttackType{
		"ftp_login_realtime": AttackAuthSuccess,
		"ssh_login_realtime": AttackBruteForce,
	} {
		db := NewForTest(nil)
		db.RecordFinding(alert.Finding{Check: check, SourceIP: "192.0.2.20", Severity: alert.Critical})
		record := db.LookupIP("192.0.2.20")
		if record == nil || record.AttackCounts[want] != 1 {
			t.Errorf("restored %s finding was not recorded as %s: %+v", check, want, record)
		}
	}
}
