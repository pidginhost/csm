package attackdb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

var auditAuthChecks = []string{
	"cpanel_file_upload_realtime", "cpanel_login", "cpanel_login_realtime",
	"ftp_login", "ftp_login_realtime", "webmail_login_realtime", "pam_login",
}

// Audit volume and successful access to multiple accounts must add no score,
// even when the same address already has unrelated attack evidence.
func TestSuccessfulAuthAddsNoScore(t *testing.T) {
	for _, check := range auditAuthChecks {
		for _, withAttack := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/attack=%v", check, withAttack), func(t *testing.T) {
				db := NewForTest(nil)
				const ip = "198.51.100.42"
				now := time.Now()
				wantScore, wantEvents := 0, 40
				if withAttack {
					db.RecordFinding(alert.Finding{Check: "suspicious_process", SourceIP: ip, TenantID: "alice", Timestamp: now})
					wantScore, wantEvents = 37, 41
				}
				for i := range 40 {
					db.RecordFinding(alert.Finding{Check: check, SourceIP: ip, TenantID: fmt.Sprintf("account%d", i%2), Timestamp: now})
				}
				rec := db.LookupIP(ip)
				if rec == nil {
					t.Fatal("audit events were lost")
				}
				if rec.EventCount != wantEvents || rec.AttackCounts[AttackAuthSuccess] != 40 || rec.Accounts["account0"] != 20 || rec.Accounts["account1"] != 20 {
					t.Fatalf("audit counts or account evidence lost: %+v", rec)
				}
				if got := computeScoreAt(rec, now); got != wantScore || rec.ThreatScore != wantScore {
					t.Fatalf("computed/stored scores = %d/%d, want %d", got, rec.ThreatScore, wantScore)
				}
				events := db.pendingEvents
				if len(events) != wantEvents || events[len(events)-1].Account != "account1" || events[len(events)-1].CheckName != check {
					t.Fatalf("audit history lost: %+v", events)
				}
			})
		}
	}
}

func TestSuccessfulAuthScoringSurvivesReload(t *testing.T) {
	for _, backend := range []string{"bbolt", "json"} {
		t.Run(backend, func(t *testing.T) {
			previous := store.Global()
			store.SetGlobal(nil)
			t.Cleanup(func() { store.SetGlobal(previous) })
			if backend == "bbolt" {
				_, cleanup := setupBboltStore(t)
				t.Cleanup(cleanup)
			}
			db := NewForTest(nil)
			db.dbPath = t.TempDir()
			const ip = "198.51.100.43"
			db.RecordFinding(alert.Finding{Check: "mail_bruteforce", SourceIP: ip, TenantID: "alice"})
			for _, account := range []string{"alice", "bob"} {
				db.RecordFinding(alert.Finding{Check: "ftp_login_realtime", SourceIP: ip, TenantID: account})
			}
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			loaded := NewForTest(nil)
			loaded.dbPath = db.dbPath
			loaded.load()
			rec := loaded.LookupIP(ip)
			if rec == nil || ComputeScore(rec) != 17 || rec.ThreatScore != 17 || rec.EventCount != 3 {
				t.Fatalf("reload changed scoring/evidence: %+v", rec)
			}
			if got := loaded.QueryEvents(ip, 10); len(got) != 3 {
				t.Fatalf("persisted events = %d, want 3", len(got))
			}
			// Alice and Bob now both have real attack evidence; the bonus
			// must activate even though they also have successful logins.
			loaded.RecordFinding(alert.Finding{Check: "mail_bruteforce", SourceIP: ip, TenantID: "bob"})
			if got := ComputeScore(loaded.LookupIP(ip)); got != 29 {
				t.Fatalf("two attacked accounts score = %d, want 29", got)
			}
		})
	}
}

func TestSuccessfulAuthSnapshotsAreDetached(t *testing.T) {
	db := NewForTest(nil)
	const ip = "198.51.100.44"
	db.RecordFinding(alert.Finding{Check: "ftp_login_realtime", SourceIP: ip, TenantID: "alice"})
	for name, snapshot := range map[string]*IPRecord{
		"lookup": db.LookupIP(ip), "all": db.AllRecords()[0], "top": db.TopAttackers(1)[0],
	} {
		before, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		db.RecordFinding(alert.Finding{Check: "ftp_login_realtime", SourceIP: ip, TenantID: "alice"})
		after, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before) {
			t.Errorf("%s snapshot changed after recording", name)
		}
	}
}

func TestFailureChecksStillScore(t *testing.T) {
	for _, check := range []string{"mail_bruteforce", "api_auth_failure", "api_auth_failure_realtime", "ftp_auth_failure_realtime", "webmail_bruteforce"} {
		t.Run(check, func(t *testing.T) {
			db := NewForTest(nil)
			const ip = "198.51.100.45"
			db.RecordFinding(alert.Finding{Check: check, SourceIP: ip})
			rec := db.LookupIP(ip)
			if rec == nil || rec.AttackCounts[AttackBruteForce] != 1 || ComputeScore(rec) != 17 {
				t.Fatalf("failure evidence/scoring changed: %+v", rec)
			}
		})
	}
}

func TestMultiIPLoginStillScores(t *testing.T) {
	db := NewForTest(nil)
	const ip = "198.51.100.46"
	db.RecordFinding(alert.Finding{Check: "cpanel_multi_ip_login", SourceIP: ip})
	rec := db.LookupIP(ip)
	if rec == nil || rec.AttackCounts[AttackCPanelLogin] != 1 || ComputeScore(rec) != 2 {
		t.Fatalf("multi-IP evidence/scoring changed: %+v", rec)
	}
}
