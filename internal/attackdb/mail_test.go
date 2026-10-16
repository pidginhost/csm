package attackdb

import (
	"encoding/json"
	"maps"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

var mailNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func TestHamNeverCreatesARecord(t *testing.T) {
	db := newTestDB(t)
	for range 1000 {
		db.RecordMailVerdict("198.51.100.20", false, mailNow)
	}
	if len(db.records) != 0 {
		t.Fatalf("ham created %d records", len(db.records))
	}
}

func TestSpamVerdictCreatesAMailOnlyRecord(t *testing.T) {
	db := newTestDB(t)
	db.RecordMailVerdict("198.51.100.21", true, mailNow)
	rec := db.records["198.51.100.21"]
	if rec == nil || rec.Mail == nil || rec.Mail.Spam != 1 || !rec.LastSeen.Equal(mailNow) || !rec.Mail.LastSpam.Equal(mailNow) {
		t.Fatalf("record %+v", rec)
	}
	if rec.EventCount != 0 || len(rec.AttackCounts) != 0 || rec.ThreatScore != 0 || len(db.pendingEvents) != 0 {
		t.Fatalf("a verdict changed threat state: %+v, events %d", rec, len(db.pendingEvents))
	}
	db.RecordMailVerdict("198.51.100.21", false, mailNow.Add(time.Minute))
	if rec.Mail.Ham != 1 || !rec.LastSeen.Equal(mailNow) {
		t.Fatalf("ham on an existing record: %+v", rec.Mail)
	}
}

// No sequence of verdicts changes EventCount, AttackCounts or ThreatScore
// (feeds spec 9.1).
func TestVerdictsNeverChangeThreatState(t *testing.T) {
	db := newTestDB(t)
	db.RecordFinding(alert.Finding{Check: "smtp_bruteforce", SourceIP: "203.0.113.30", Timestamp: mailNow, Message: "x"})
	rec := db.records["203.0.113.30"]
	events, counts, score := rec.EventCount, maps.Clone(rec.AttackCounts), rec.ThreatScore
	r := rand.New(rand.NewSource(1))
	at := mailNow
	for range 500 {
		at = at.Add(time.Duration(r.Intn(3600)) * time.Second)
		db.RecordMailVerdict("203.0.113.30", r.Intn(2) == 0, at)
	}
	if rec.EventCount != events || !reflect.DeepEqual(rec.AttackCounts, counts) || rec.ThreatScore != score {
		t.Fatalf("verdicts changed threat state: %+v", rec)
	}
}

func TestSpamScoreDecays(t *testing.T) {
	db := newTestDB(t)
	db.RecordMailVerdict("198.51.100.22", true, mailNow)
	db.RecordMailVerdict("198.51.100.22", true, mailNow)
	m := db.records["198.51.100.22"].Mail
	if got := SpamScore(m, mailNow); got != 50 {
		t.Fatalf("two fresh spam = %d, want 50", got)
	}
	if got := SpamScore(m, mailNow.Add(7*24*time.Hour)); got != 33 {
		t.Fatalf("a week later = %d, want 33", got)
	}
	if SpamScore(nil, mailNow) != 0 {
		t.Fatal("nil mail section scores")
	}
}

func TestMailAuthCountsOnlyMailChecks(t *testing.T) {
	db := newTestDB(t)
	for _, check := range []string{"smtp_bruteforce", "smtp_probe_abuse", "mail_bruteforce", "mail_account_compromised"} {
		db.RecordFinding(alert.Finding{Check: check, SourceIP: "203.0.113.31", Timestamp: mailNow, Message: "x"})
	}
	db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: "203.0.113.32", Timestamp: mailNow, Message: "x"})
	if m := db.records["203.0.113.31"].Mail; m == nil || m.AuthAttacks != 4 || !m.LastAuthAttack.Equal(mailNow) {
		t.Fatalf("mail auth = %+v", m)
	}
	if db.records["203.0.113.32"].Mail != nil {
		t.Fatal("a web login attack got a mail section")
	}
}

func TestMapSources(t *testing.T) {
	db := newTestDB(t)
	db.RecordFinding(alert.Finding{Check: "mail_bruteforce", SourceIP: "203.0.113.40", Timestamp: mailNow.Add(-29 * 24 * time.Hour), Message: "x"})
	db.RecordFinding(alert.Finding{Check: "mail_bruteforce", SourceIP: "203.0.113.41", Timestamp: mailNow.Add(-31 * 24 * time.Hour), Message: "x"})
	db.RecordMailVerdict("198.51.100.40", true, mailNow)
	db.RecordMailVerdict("198.51.100.40", true, mailNow)
	db.RecordMailVerdict("198.51.100.41", true, mailNow)
	auth, spam := db.MapSources(mailNow)
	if !reflect.DeepEqual(auth, []string{"203.0.113.40"}) || !reflect.DeepEqual(spam, []string{"198.51.100.40"}) {
		t.Fatalf("auth %v, spam %v", auth, spam)
	}
}

func TestTopSpamSenders(t *testing.T) {
	db := newTestDB(t)
	db.RecordMailVerdict("198.51.100.50", true, mailNow)
	for range 3 {
		db.RecordMailVerdict("198.51.100.51", true, mailNow)
	}
	db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: "203.0.113.50", Timestamp: mailNow, Message: "x"})
	got := db.TopSpamSenders(10, mailNow)
	if len(got) != 2 || got[0].IP != "198.51.100.51" || got[1].IP != "198.51.100.50" {
		t.Fatalf("top spam senders %v", got)
	}
	got[0].Mail.Spam = 99
	if db.records["198.51.100.51"].Mail.Spam == 99 {
		t.Fatal("TopSpamSenders returned live mail sections")
	}
}

func TestStoreConversionKeepsMail(t *testing.T) {
	rec := &IPRecord{IP: "198.51.100.60", AttackCounts: map[AttackType]int{}, Accounts: map[string]int{},
		Mail: &MailEvidence{Spam: 2, Ham: 1, SpamMass: 1.5, HamMass: 0.5, MassAt: mailNow, LastSpam: mailNow, AuthAttacks: 3, LastAuthAttack: mailNow}}
	sr := toStoreIPRecord(rec)
	data, err := json.Marshal(sr)
	if err != nil {
		t.Fatal(err)
	}
	var back store.IPRecord
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if got := fromStoreIPRecord(&back); !reflect.DeepEqual(got.Mail, rec.Mail) {
		t.Fatalf("mail = %+v, want %+v", got.Mail, rec.Mail)
	}
	sr.Mail.Spam = 7
	if rec.Mail.Spam == 7 {
		t.Fatal("store record aliases the live mail section")
	}
}

// Old builds counted spam from message text; those counts are still
// dropped, but a record with a mail section is never dropped as empty.
func TestLoaderKeepsMailRecords(t *testing.T) {
	rec := &IPRecord{IP: "198.51.100.61", EventCount: 2, AttackCounts: map[AttackType]int{AttackSPAM: 2}, Accounts: map[string]int{},
		Mail: &MailEvidence{Spam: 1, SpamMass: 1, MassAt: mailNow}}
	changed, emptied := normalizeLoadedRecord(rec)
	if !changed || emptied || rec.EventCount != 0 || rec.AttackCounts[AttackSPAM] != 0 || rec.Mail == nil {
		t.Fatalf("changed=%v emptied=%v record %+v", changed, emptied, rec)
	}
	old := &IPRecord{IP: "198.51.100.62", EventCount: 1, AttackCounts: map[AttackType]int{AttackSPAM: 1}, Accounts: map[string]int{}}
	if _, emptied := normalizeLoadedRecord(old); !emptied {
		t.Fatal("a record of only old spam counts is kept")
	}
}

func TestCloneCopiesMail(t *testing.T) {
	rec := &IPRecord{IP: "198.51.100.63", Mail: &MailEvidence{Spam: 1}}
	cp := cloneIPRecord(rec)
	cp.Mail.Spam = 5
	if rec.Mail.Spam != 1 {
		t.Fatal("clone shares the mail section")
	}
}
