package attackdb

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// scoringAttackTypes are the types that add a bonus in computeScoreAt. A
// successful authentication must set none of them.
var scoringAttackTypes = []AttackType{
	AttackC2, AttackWebshell, AttackPhishing, AttackBruteForce, AttackFileUpload,
}

// cpanel_file_upload_realtime was the only producer of AttackFileUpload,
// which adds a flat 20 to the threat score. The check fires on a SUCCESSFUL,
// authenticated File Manager write, so an ordinary customer upload scored the
// customer's own address 20 points.
//
// ComputeScore has no recency term and records are kept for 90 days, so that
// 20 never decayed. On a production host the account owner's address reached
// 50/100 this way, which then fed local_threat_score and the reputation path
// that kept re-blocking it.
//
// Recording the event is still right -- it is evidence when correlated with
// other findings on the same account. Scoring the address as an attacker for
// using a core cPanel feature is not.
func TestSuccessfulFileUploadDoesNotScoreAsAttack(t *testing.T) {
	db := NewForTest(nil)
	const ip = "198.51.100.42"

	db.RecordFinding(alert.Finding{
		Check:     "cpanel_file_upload_realtime",
		SourceIP:  ip,
		Timestamp: time.Now(),
		Message:   "cPanel File Manager write from non-infra IP: " + ip,
	})

	rec := db.LookupIP(ip)
	if rec == nil {
		t.Fatal("the event was not recorded at all; it should still be retained as evidence")
	}
	if n := rec.AttackCounts[AttackFileUpload]; n != 0 {
		t.Errorf("AttackFileUpload count = %d, want 0: a successful authenticated upload is not an attack", n)
	}
	if got := ComputeScore(rec); got >= 20 {
		t.Errorf("score = %d; the flat file-upload attack bonus is still being applied", got)
	}
}

// A successful FTP or webmail login is the same class of event: the user
// authenticated. It must not accrue attack-type weight either.
func TestSuccessfulLoginsDoNotScoreAsAttack(t *testing.T) {
	// Every one of these fires only after the user authenticated.
	// cpanel_multi_ip_login is deliberately absent: it is a threshold signal
	// (several addresses inside a window), which is genuine correlation
	// evidence and must keep scoring.
	for _, check := range []string{
		"ftp_login_realtime", "ftp_login", "webmail_login_realtime",
		"cpanel_login", "cpanel_login_realtime", "pam_login",
	} {
		t.Run(check, func(t *testing.T) {
			db := NewForTest(nil)
			const ip = "198.51.100.43"
			db.RecordFinding(alert.Finding{Check: check, SourceIP: ip, Timestamp: time.Now()})

			rec := db.LookupIP(ip)
			if rec == nil {
				t.Fatal("event not recorded")
			}
			for _, scoring := range scoringAttackTypes {
				if n := rec.AttackCounts[scoring]; n > 0 {
					t.Errorf("%s recorded scoring attack type %q (count %d); a successful login is not an attack", check, scoring, n)
				}
			}
			if got := ComputeScore(rec); got > 2 {
				t.Errorf("%s scored %d for a single successful login", check, got)
			}
		})
	}
}

// Failure and brute-force checks must keep scoring, or removing the success
// checks would quietly disarm the threat database.
func TestFailureChecksStillScore(t *testing.T) {
	db := NewForTest(nil)
	const ip = "198.51.100.44"
	for i := 0; i < 3; i++ {
		db.RecordFinding(alert.Finding{Check: "mail_bruteforce", SourceIP: ip, Timestamp: time.Now()})
	}
	rec := db.LookupIP(ip)
	if rec == nil {
		t.Fatal("brute-force event not recorded")
	}
	if rec.AttackCounts[AttackBruteForce] == 0 {
		t.Error("brute force no longer records an attack type")
	}
}

// cpanel_multi_ip_login reports the same account authenticating from several
// addresses inside a window. That is correlation evidence rather than a
// single successful login, so it keeps its attack weight.
func TestMultiIPLoginStillScores(t *testing.T) {
	db := NewForTest(nil)
	const ip = "198.51.100.45"
	db.RecordFinding(alert.Finding{Check: "cpanel_multi_ip_login", SourceIP: ip, Timestamp: time.Now()})
	rec := db.LookupIP(ip)
	if rec == nil || rec.AttackCounts[AttackCPanelLogin] == 0 {
		t.Error("cpanel_multi_ip_login no longer records an attack type")
	}
}
