package attackdb

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestMailVerdictsUseCanonicalIP(t *testing.T) {
	for _, tc := range []struct {
		raw, canonical string
	}{
		{"::ffff:198.51.100.70", "198.51.100.70"},
		{" 198.51.100.70:25 ", "198.51.100.70"},
		{"2001:0db8:0:0:0:0:0:70", "2001:db8::70"},
		{"[2001:db8::70]:25", "2001:db8::70"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			db := newTestDB(t)
			db.RecordMailVerdict(tc.raw, true, mailNow)
			db.RecordFinding(alert.Finding{Check: "smtp_bruteforce", SourceIP: tc.canonical, Timestamp: mailNow})
			db.RecordMailVerdict(tc.canonical, true, mailNow)
			auth, spam := db.MapSources(mailNow)
			want := []string{tc.canonical}
			if !reflect.DeepEqual(auth, want) || !reflect.DeepEqual(spam, want) {
				t.Errorf("map sources = %v, %v; want %v for both", auth, spam, want)
			}
			db.RecordMailVerdict(tc.raw, false, mailNow)
			rec := db.LookupIP(tc.canonical)
			if db.TotalIPs() != 1 || rec == nil || rec.Mail == nil || rec.Mail.Spam != 2 || rec.Mail.Ham != 1 || rec.Mail.AuthAttacks != 1 {
				t.Fatalf("equivalent addresses split evidence: records=%d canonical=%+v", db.TotalIPs(), rec)
			}
		})
	}
}

func TestMailVerdictsRejectInvalidIP(t *testing.T) {
	for _, ip := range []string{"", " ", "sender.example", "198.51.100.0/24", "198.51.100.70\n203.0.113.70"} {
		t.Run(ip, func(t *testing.T) {
			db := newTestDB(t)
			db.RecordMailVerdict(ip, true, mailNow)
			if db.TotalIPs() != 0 || db.dirty || len(db.dirtyIPs) != 0 {
				t.Fatalf("invalid address queued a record: records=%d dirty=%v", db.TotalIPs(), db.dirty)
			}
		})
	}
}

func TestMailVerdictsDecayLateEvidence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		oldSpam    bool
		old, fresh int
		spamMass   float64
		hamMass    float64
		spam, ham  int
		score      int
		listed     bool
	}{
		{"late spam", true, 2, 1, 0.5, 1, 2, 1, 14, false},
		{"late ham", false, 2, 3, 3, 0.5, 3, 2, 55, true},
	} {
		for _, late := range []bool{false, true} {
			name := tc.name + "/ordered"
			if late {
				name = tc.name + "/reversed"
			}
			t.Run(name, func(t *testing.T) {
				db := newTestDB(t)
				const ip = "198.51.100.71"
				db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: ip, Timestamp: mailNow.Add(-21 * 24 * time.Hour)})
				oldAt := mailNow.Add(-14 * 24 * time.Hour)
				old := func() {
					for range tc.old {
						db.RecordMailVerdict(ip, tc.oldSpam, oldAt)
					}
				}
				fresh := func() {
					for range tc.fresh {
						db.RecordMailVerdict(ip, !tc.oldSpam, mailNow)
					}
				}
				if late {
					fresh()
					old()
				} else {
					old()
					fresh()
				}
				rec := db.LookupIP(ip)
				m := rec.Mail
				if m.SpamMass != tc.spamMass || m.HamMass != tc.hamMass || !m.MassAt.Equal(mailNow) {
					t.Errorf("masses = %+v; want spam=%v ham=%v at %v", m, tc.spamMass, tc.hamMass, mailNow)
				}
				if m.Spam != tc.spam || m.Ham != tc.ham || SpamScore(m, mailNow) != tc.score {
					t.Errorf("counts/score = %+v, %d; want spam=%d ham=%d score=%d", m, SpamScore(m, mailNow), tc.spam, tc.ham, tc.score)
				}
				lastSpam := mailNow
				if tc.oldSpam {
					lastSpam = oldAt
				}
				if !rec.LastSeen.Equal(lastSpam) || !m.LastSpam.Equal(lastSpam) {
					t.Errorf("spam activity dates = %v, %v; want %v", rec.LastSeen, m.LastSpam, lastSpam)
				}
				_, spam := db.MapSources(mailNow)
				var want []string
				if tc.listed {
					want = []string{ip}
				}
				if !reflect.DeepEqual(spam, want) {
					t.Errorf("spam sources = %v; want %v", spam, want)
				}
			})
		}
	}
}

func TestMailVerdictWithoutTimestampUsesCurrentTime(t *testing.T) {
	db := newTestDB(t)
	before := time.Now()
	db.RecordMailVerdict("198.51.100.72", true, time.Time{})
	after := time.Now()
	db.PruneExpired()
	rec := db.LookupIP("198.51.100.72")
	if rec == nil {
		t.Fatal("new spam record was immediately pruned")
	}
	for _, at := range []time.Time{rec.FirstSeen, rec.LastSeen, rec.Mail.LastSpam, rec.Mail.MassAt} {
		if at.Before(before) || at.After(after) {
			t.Errorf("activity timestamp = %v; want between %v and %v", at, before, after)
		}
	}
	if got := SpamScore(rec.Mail, after); got != 33 {
		t.Errorf("fresh spam score = %d, want 33", got)
	}
}

func TestTopSpamSendersNonPositiveLimit(t *testing.T) {
	db := newTestDB(t)
	db.RecordMailVerdict("198.51.100.73", true, mailNow)
	for _, n := range []int{0, -1} {
		if got := db.TopSpamSenders(n, mailNow); len(got) != 0 {
			t.Errorf("TopSpamSenders(%d) returned %d records, want none", n, len(got))
		}
	}
}

func TestMailEvidenceSurvivesRestart(t *testing.T) {
	for _, backend := range []string{"json", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "bbolt" {
				_, cleanup := setupBboltStore(t)
				defer cleanup()
			}
			db := newTestDB(t)
			const ip = "198.51.100.74"
			db.RecordMailVerdict(ip, true, mailNow)
			db.RecordMailVerdict(ip, false, mailNow.Add(-14*24*time.Hour))
			want := db.LookupIP(ip)
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			reloaded := newTestDB(t)
			reloaded.dbPath = db.dbPath
			reloaded.load()
			if got := reloaded.LookupIP(ip); !reflect.DeepEqual(got, want) {
				t.Fatalf("reloaded record = %+v, want %+v", got, want)
			}
			// A mail-only record must accept later attack and verdict updates.
			reloaded.RecordFinding(alert.Finding{Check: "smtp_bruteforce", SourceIP: ip, Mailbox: "user@example.com", Timestamp: mailNow})
			reloaded.RecordMailVerdict(ip, true, mailNow)
			if err := reloaded.Flush(); err != nil {
				t.Fatal(err)
			}
			db.load()
			got := db.LookupIP(ip)
			if got == nil || got.EventCount != 1 || got.AttackCounts[AttackBruteForce] != 1 || got.Accounts["user@example.com"] != 1 || got.Mail.AuthAttacks != 1 || got.Mail.Spam != 2 || got.Mail.Ham != 1 || got.Mail.SpamMass != 2 || got.Mail.HamMass != 0.25 {
				t.Fatalf("mail evidence or attack state lost after restart: %+v", got)
			}
			if got := db.QueryEvents(ip, 10); len(got) != 1 || got[0].CheckName != "smtp_bruteforce" {
				t.Fatalf("mail verdicts changed event history: %+v", got)
			}
		})
	}
}

func TestConcurrentMailVerdictsAndSnapshots(t *testing.T) {
	db := newTestDB(t)
	const ip = "198.51.100.75"
	const count = 50
	db.RecordMailVerdict(ip, true, mailNow)
	var wg sync.WaitGroup
	for _, spam := range []bool{false, true} {
		wg.Go(func() {
			for range count {
				db.RecordMailVerdict(ip, spam, mailNow)
			}
		})
	}
	wg.Go(func() {
		for range count {
			db.LookupIP(ip).Mail.Spam = -1
			db.TopSpamSenders(1, mailNow)[0].Mail.Ham = -1
			if err := db.Flush(); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Wait()
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	db.load()
	m := db.LookupIP(ip).Mail
	if m.Spam != count+1 || m.Ham != count || m.SpamMass != count+1 || m.HamMass != count {
		t.Fatalf("concurrent updates or snapshot mutations lost evidence: %+v", m)
	}
}
