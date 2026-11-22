package attackdb

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestUnverifiedFTPDoesNotFeedAttackState(t *testing.T) {
	for _, producer := range []string{"ftp_log", "ftp_scan", "ftp_journal"} {
		for _, check := range []string{"ftp_auth_failure_realtime", "ftp_bruteforce", "ftp_login"} {
			t.Run(producer+"/"+check, func(t *testing.T) {
				db := NewForTest(nil)
				db.RecordFinding(alert.Finding{Check: check, SourceIP: "198.51.100.7", TenantID: "alice", Observation: alert.Observation{Producer: producer}})
				got := db.LookupIP("198.51.100.7")
				if producer == "ftp_journal" {
					if got == nil || got.EventCount != 1 {
						t.Fatalf("trusted FTP event lost: %+v", got)
					}
				} else if got != nil || len(db.pendingEvents) != 0 {
					t.Fatalf("unverified FTP entered attack state: %+v", got)
				}
			})
		}
	}
}
