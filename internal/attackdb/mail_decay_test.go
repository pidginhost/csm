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

func TestDecayDropStoredEvidence(t *testing.T) {
	for _, backend := range []string{"json", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			for _, tt := range []struct {
				name   string
				ip     string
				mail   MailEvidence
				keep   bool
				listed bool
			}{
				{"missing clock spam", "192.0.2.30", MailEvidence{Spam: 3, SpamMass: 3}, true, true},
				{"missing clock ham", "192.0.2.31", MailEvidence{Spam: 1, Ham: 3, SpamMass: 0.001, HamMass: 3}, true, false},
				{"missing clock faded", "192.0.2.32", MailEvidence{Spam: 1, SpamMass: 0.001}, false, false},
				{"future clock", "192.0.2.33", MailEvidence{Spam: 3, SpamMass: 3, MassAt: mailNow.Add(day)}, true, true},
				{"spam at floor", "192.0.2.34", MailEvidence{Spam: 1, SpamMass: 0.02, MassAt: mailNow.Add(-7 * day)}, true, false},
				{"ham at floor", "192.0.2.35", MailEvidence{Spam: 1, Ham: 1, HamMass: 0.02, MassAt: mailNow.Add(-7 * day)}, true, false},
				{"faded legacy IPv6", "2001:db8:1:2::6", MailEvidence{Spam: 1, SpamMass: 1, MassAt: mailNow.Add(-47 * day)}, false, false},
			} {
				t.Run(tt.name, func(t *testing.T) {
					if backend == "bbolt" {
						_, cleanup := setupBboltStore(t)
						t.Cleanup(cleanup)
					}
					db := newTestDB(t)
					rec := &IPRecord{IP: tt.ip, LastSeen: mailNow, Mail: &tt.mail}
					db.records[tt.ip] = rec
					db.markDirtyLocked(tt.ip)
					if err := db.Flush(); err != nil {
						t.Fatal(err)
					}
					loaded := NewForTest(nil)
					loaded.dbPath = db.dbPath
					loaded.load()
					if got := loaded.records[tt.ip]; got == nil || got.Mail == nil || *got.Mail != tt.mail {
						t.Fatalf("stored evidence did not round trip: %+v", got)
					}
					_, before := loaded.MapSources(mailNow)
					if got := slices.Contains(before, tt.ip); got != tt.listed {
						t.Fatalf("listed before prune = %v, want %v", got, tt.listed)
					}
					loaded.pruneExpiredAt(mailNow)
					got, kept := loaded.records[tt.ip]
					if kept != tt.keep {
						t.Fatalf("kept = %v, want %v", kept, tt.keep)
					}
					if kept && *got.Mail != tt.mail {
						t.Error("pruning changed retained evidence")
					}
					_, after := loaded.MapSources(mailNow)
					if !slices.Equal(before, after) {
						t.Errorf("listed senders changed: before %v, after %v", before, after)
					}
					if err := loaded.Flush(); err != nil {
						t.Fatal(err)
					}
					reloaded := NewForTest(nil)
					reloaded.dbPath = db.dbPath
					reloaded.load()
					if _, ok := reloaded.records[tt.ip]; ok != tt.keep {
						t.Errorf("persisted record kept = %v, want %v", ok, tt.keep)
					}
				})
			}
		})
	}
}

func TestNinetyDayRuleIgnoresRecentHam(t *testing.T) {
	const expired, boundary = "192.0.2.36", "192.0.2.37"
	db := NewForTest(nil)
	db.RecordMailVerdict(expired, true, mailNow.Add(-90*day-time.Nanosecond))
	db.RecordMailVerdict(boundary, true, mailNow.Add(-90*day))
	for _, ip := range []string{expired, boundary} {
		db.RecordMailVerdict(ip, false, mailNow)
	}
	db.pruneExpiredAt(mailNow)
	if got, want := recordKeys(db), []string{boundary}; !slices.Equal(got, want) {
		t.Errorf("records after prune = %v, want %v", got, want)
	}
	if _, ok := db.deletedIPs[expired]; !ok {
		t.Error("the expired mail record is not marked deleted")
	}
}
