package attackdb

import (
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

const day = 24 * time.Hour

func TestDecayDropRemovesSingleOldVerdict(t *testing.T) {
	const faded, fading = "192.0.2.20", "192.0.2.21"
	db := NewForTest(nil)
	db.RecordMailVerdict(faded, true, mailNow.Add(-47*day))
	db.RecordMailVerdict(fading, true, mailNow.Add(-45*day))

	db.pruneExpiredAt(mailNow)

	if _, ok := db.records[faded]; ok {
		t.Error("a single spam verdict 47 days old was kept")
	}
	if _, ok := db.deletedIPs[faded]; !ok {
		t.Error("the dropped record is not marked deleted")
	}
	if _, ok := db.records[fading]; !ok {
		t.Error("a single spam verdict 45 days old was dropped")
	}
}

func TestDecayDropKeepsHamHistory(t *testing.T) {
	const ip = "192.0.2.22"
	db := NewForTest(nil)
	db.RecordMailVerdict(ip, true, mailNow.Add(-60*day))
	for age := 59; age >= 0; age-- {
		db.RecordMailVerdict(ip, false, mailNow.Add(-time.Duration(age)*day))
	}

	db.pruneExpiredAt(mailNow)

	rec := db.records[ip]
	if rec == nil {
		t.Fatal("a record with ham history was dropped")
	}
	db.RecordMailVerdict(ip, true, mailNow)
	db.RecordMailVerdict(ip, true, mailNow)
	if got := SpamScore(rec.Mail, mailNow); got >= SpamListScore {
		t.Errorf("spam score after two new spam verdicts = %d, want below %d", got, SpamListScore)
	}
}

func TestDecayDropKeepsRecordsThatAreNotMailOnly(t *testing.T) {
	const control, finding, blocked, login = "192.0.2.23", "192.0.2.24", "192.0.2.25", "192.0.2.26"
	old := mailNow.Add(-60 * day)
	db := NewForTest(map[string]*IPRecord{
		login: {IP: login, Mail: &MailEvidence{AuthAttacks: 1, LastAuthAttack: mailNow.Add(-10 * day)}},
	})
	for _, ip := range []string{control, finding, blocked, login} {
		db.RecordMailVerdict(ip, true, old)
	}
	db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: finding, Timestamp: old, Message: "x"})
	db.MarkBlocked(blocked)

	db.pruneExpiredAt(mailNow)

	if got, want := recordKeys(db), []string{finding, blocked, login}; !slices.Equal(got, want) {
		t.Errorf("records after prune = %v, want %v", got, want)
	}
}

func TestInitPruneKeepsListedSenders(t *testing.T) {
	const listed, legacy = "192.0.2.27", "2001:db8:1:2::5"
	db := NewForTest(map[string]*IPRecord{
		legacy: {IP: legacy, LastSeen: mailNow, Mail: &MailEvidence{Spam: 3, SpamMass: 3, MassAt: mailNow}},
	})
	for range 3 {
		db.RecordMailVerdict(listed, true, mailNow.Add(-3*day))
	}

	db.pruneExpiredAt(mailNow)

	want := []string{listed, legacy}
	if got := recordKeys(db); !slices.Equal(got, want) {
		t.Errorf("records after prune = %v, want %v", got, want)
	}
	if _, spam := db.MapSources(mailNow); !slices.Equal(spam, want) {
		t.Errorf("spam sources after prune = %v, want %v", spam, want)
	}
}

func TestNinetyDayRuleUnchanged(t *testing.T) {
	const expired, live = "192.0.2.28", "192.0.2.29"
	db := NewForTest(nil)
	db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: expired, Timestamp: mailNow.Add(-91 * day), Message: "x"})
	db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: live, Timestamp: mailNow.Add(-89 * day), Message: "x"})

	db.pruneExpiredAt(mailNow)

	if got, want := recordKeys(db), []string{live}; !slices.Equal(got, want) {
		t.Errorf("records after prune = %v, want %v", got, want)
	}
	if _, ok := db.deletedIPs[expired]; !ok {
		t.Error("the expired record is not marked deleted")
	}
}
