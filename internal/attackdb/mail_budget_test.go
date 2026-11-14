package attackdb

import (
	"fmt"
	"math/rand"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// thinIP is an address alone in its /48. 2001:db8:7::/48 is never one of them.
func thinIP(n int) string { return fmt.Sprintf("2001:db8:%x:1::1", 0x100+n) }

// storedSpam is a mail-only record as a store holds it.
func storedSpam(key string, spamMass, hamMass float64, massAt time.Time) *IPRecord {
	return &IPRecord{IP: key, FirstSeen: mailNow, LastSeen: mailNow, Mail: &MailEvidence{Spam: 1, SpamMass: spamMass, HamMass: hamMass, MassAt: massAt}}
}

func mailOnlyAt(db *DB, at time.Time) int {
	n := 0
	for _, rec := range db.records {
		if mailOnly(rec, at) {
			n++
		}
	}
	return n
}

func TestNoEvictionAtOrUnderBudget(t *testing.T) {
	db := NewForTest(nil)
	db.SetMailBudget(100)
	for n := range 100 {
		if ev := db.RecordMailVerdict(thinIP(n), true, mailNow); ev != nil {
			t.Fatalf("verdict %d reported an eviction: %+v", n, ev)
		}
	}
	// More verdicts about a sender at the budget create nothing.
	if ev := db.RecordMailVerdict(thinIP(0), true, mailNow); ev != nil {
		t.Fatalf("a verdict on an existing record reported an eviction: %+v", ev)
	}
	if len(db.records) != 100 || len(db.deletedIPs) != 0 || db.mailEvicted != 0 {
		t.Fatalf("%d records, %d deleted, %d evicted, want 100, 0, 0", len(db.records), len(db.deletedIPs), db.mailEvicted)
	}
	if db.mailOnlyCount != 100 {
		t.Errorf("count = %d after 100 new records and one more verdict, want 100", db.mailOnlyCount)
	}
}

// The crowded network's records are fresh and the others three days old, so
// the crowd has to outrank the lower mass.
func TestEvictionTakesCrowdedNetworkFirst(t *testing.T) {
	for _, tt := range []struct {
		name, network string
		ip            func(n int) string
		stored        bool
	}{
		{"IPv6 /48", "2001:db8:7::/48", func(n int) string { return fmt.Sprintf("2001:db8:7:%x::1", n+1) }, false},
		{"IPv4 /16", "192.0.0.0/16", func(n int) string { return fmt.Sprintf("192.0.2.%d", n+1) }, false},
		{"stored per-address IPv6", "2001:db8:7::/48", func(n int) string { return fmt.Sprintf("2001:db8:7:%x::9", n+1) }, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			crowd := make([]string, 41)
			stored := map[string]*IPRecord{}
			for n := range crowd {
				crowd[n] = mailRecordKey(tt.ip(n))
				if tt.stored && n < 40 {
					crowd[n] = tt.ip(n)
					stored[crowd[n]] = storedSpam(crowd[n], 1, 0, mailNow)
				}
			}
			db := NewForTest(stored)
			db.SetMailBudget(100)
			thin := make([]string, 60)
			for n := range thin {
				thin[n] = mailRecordKey(thinIP(n))
				if ev := db.RecordMailVerdict(thinIP(n), true, mailNow.Add(-3*day)); ev != nil {
					t.Fatalf("eviction under the budget: %+v", ev)
				}
			}
			var report *Eviction
			for n, key := range crowd {
				if _, ok := db.records[key]; ok {
					continue
				}
				if report != nil {
					t.Fatalf("eviction under the budget: %+v", report)
				}
				report = db.RecordMailVerdict(tt.ip(n), true, mailNow)
			}

			if want := (Eviction{Dropped: 11, Network: tt.network, NetworkRecords: 41}); report == nil || *report != want {
				t.Fatalf("report = %+v, want %+v", report, want)
			}
			for _, key := range thin {
				if _, ok := db.records[key]; !ok {
					t.Fatalf("%s, alone in its network, was evicted", key)
				}
			}
			// Equal mass inside the crowd: the smallest keys go.
			slices.Sort(crowd)
			want := append(slices.Clone(crowd[11:]), thin...)
			slices.Sort(want)
			if got := recordKeys(db); !slices.Equal(got, want) {
				t.Errorf("records after the pass = %v, want %v", got, want)
			}
			if db.mailOnlyCount != 90 {
				t.Errorf("count after the pass = %d, want 90", db.mailOnlyCount)
			}
		})
	}
}

// The protected senders share one /16, so a crowd must never outrank mass above 1.
func TestThinFloodNeverEvictsStrongerEvidence(t *testing.T) {
	db := NewForTest(nil)
	db.SetMailBudget(100)
	var protected []string
	for n := range 30 {
		ip := fmt.Sprintf("198.51.100.%d", n+1)
		protected = append(protected, ip)
		spam, ham := 2, 0
		switch n / 10 {
		case 1:
			spam = 3
		case 2:
			spam, ham = 1, 5
		}
		for range spam {
			db.RecordMailVerdict(ip, true, mailNow)
		}
		for range ham {
			db.RecordMailVerdict(ip, false, mailNow)
		}
	}
	_, listed := db.MapSources(mailNow)
	if len(listed) != 20 {
		t.Fatalf("%d listed senders before the flood, want 20", len(listed))
	}

	for n := range 200 {
		at := mailNow.Add(time.Duration(n) * time.Second)
		db.RecordMailVerdict(thinIP(n), true, at)
		if got := mailOnlyAt(db, at); got > 100 {
			t.Fatalf("%d mail-only records after flood message %d, budget 100", got, n)
		}
		for _, ip := range protected {
			if _, ok := db.records[ip]; !ok {
				t.Fatalf("flood message %d evicted %s", n, ip)
			}
		}
	}

	// 101 records at flood message 71, then one pass per 11 messages.
	if db.mailEvicted != 132 || len(db.records) != 98 {
		t.Fatalf("%d evicted, %d records left, want 132 and 98", db.mailEvicted, len(db.records))
	}
	if _, after := db.MapSources(mailNow); !slices.Equal(after, listed) {
		t.Errorf("listed senders after the flood = %v, want %v", after, listed)
	}
}

// Two verdicts keep a record above the single-verdict level however far its
// mass has decayed, so no number of one-message senders reaches it.
func TestThinFloodNeverEvictsDecayedMultiVerdictEvidence(t *testing.T) {
	const twoVerdicts, hamHistory = "198.51.100.1", "198.51.100.2"
	db := NewForTest(nil)
	db.SetMailBudget(100)
	db.RecordMailVerdict(twoVerdicts, true, mailNow.Add(-8*day))
	db.RecordMailVerdict(twoVerdicts, true, mailNow.Add(-8*day))
	db.RecordMailVerdict(hamHistory, true, mailNow.Add(-19*day))
	for range 5 {
		db.RecordMailVerdict(hamHistory, false, mailNow.Add(-19*day))
	}
	for _, ip := range []string{twoVerdicts, hamHistory} {
		m := *db.records[ip].Mail
		decayTo(&m, mailNow)
		if mass := m.SpamMass + m.HamMass; mass > 1 {
			t.Fatalf("fixture %s has mass %.2f, want at most 1", ip, mass)
		}
	}

	for n := range 150 {
		db.RecordMailVerdict(thinIP(n), true, mailNow.Add(time.Duration(n)*time.Second))
		for _, ip := range []string{twoVerdicts, hamHistory} {
			if _, ok := db.records[ip]; !ok {
				t.Fatalf("flood message %d evicted %s", n, ip)
			}
		}
	}

	// 101 records at flood message 99, then one pass per 11 messages.
	if db.mailEvicted != 55 || len(db.records) != 97 {
		t.Fatalf("%d evicted, %d records left, want 55 and 97", db.mailEvicted, len(db.records))
	}
}

// The flood's records reach the listed sender's level, and there the most
// crowded network pays first.
func TestMultiMessageFloodFromOneNetworkLosesItsOwnFirst(t *testing.T) {
	const listed = "198.51.100.1"
	db := NewForTest(nil)
	db.SetMailBudget(100)
	for range 3 {
		db.RecordMailVerdict(listed, true, mailNow.Add(-26*time.Hour))
	}

	var reports []Eviction
	for n := range 200 {
		for range 3 {
			if ev := db.RecordMailVerdict(fmt.Sprintf("2001:db8:7:%x::1", n+1), true, mailNow); ev != nil {
				reports = append(reports, *ev)
			}
			if _, ok := db.records[listed]; !ok {
				t.Fatalf("the flood's /64 number %d evicted the listed sender", n+1)
			}
		}
	}

	// A pass at the 100th /64 and at every tenth after it; one report a day.
	if want := []Eviction{{Dropped: 11, Network: "2001:db8:7::/48", NetworkRecords: 100}}; !slices.Equal(reports, want) {
		t.Errorf("reports = %+v, want %+v", reports, want)
	}
	if db.mailEvicted != 121 || len(db.records) != 91 {
		t.Errorf("%d evicted, %d records left, want 121 and 91", db.mailEvicted, len(db.records))
	}
	if _, spam := db.MapSources(mailNow); !slices.Contains(spam, listed) {
		t.Errorf("the listed sender left the spam sources: %v", spam)
	}
}

// Twenty senders with ten verdicts each share a /16. Senders of two
// messages, each alone in its network, never reach them.
func TestCrowdNeverOutranksLevel(t *testing.T) {
	db := NewForTest(nil)
	db.SetMailBudget(100)
	var clustered []string
	for n := range 20 {
		ip := fmt.Sprintf("198.51.100.%d", n+1)
		clustered = append(clustered, ip)
		for range 10 {
			db.RecordMailVerdict(ip, true, mailNow)
		}
	}

	for n := range 150 {
		for range 2 {
			db.RecordMailVerdict(thinIP(n), true, mailNow)
			for _, ip := range clustered {
				if _, ok := db.records[ip]; !ok {
					t.Fatalf("two-message sender %d evicted %s", n, ip)
				}
			}
		}
	}

	// A pass at sender 81 and at every tenth after it.
	if db.mailEvicted != 77 || len(db.records) != 100 {
		t.Fatalf("%d evicted, %d records left, want 77 and 100", db.mailEvicted, len(db.records))
	}
}

func TestEvictionLevel(t *testing.T) {
	for _, tt := range []struct {
		name string
		mail MailEvidence
		want float64
	}{
		{"one fresh verdict", MailEvidence{Spam: 1, SpamMass: 1}, 1},
		{"one faded verdict", MailEvidence{Spam: 1, SpamMass: 0.02}, 1},
		{"no mass", MailEvidence{}, 1},
		{"two old verdicts", MailEvidence{Spam: 2, SpamMass: 0.91}, 2},
		{"old spam and ham", MailEvidence{Spam: 1, Ham: 1, SpamMass: 0.3, HamMass: 0.3}, 2},
		{"two fresh verdicts", MailEvidence{Spam: 2, SpamMass: 2}, 2},
		{"just over two", MailEvidence{Spam: 3, SpamMass: 2.01}, 3},
		{"three verdicts a day old", MailEvidence{Spam: 3, SpamMass: 2.7}, 3},
		{"three fresh verdicts", MailEvidence{Spam: 3, SpamMass: 3}, 3},
		{"ham counts", MailEvidence{Spam: 1, Ham: 5, SpamMass: 1, HamMass: 4.5}, 6},
	} {
		if got := mailLevel(&tt.mail); got != tt.want {
			t.Errorf("%s: level %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestHeavierRecordsGoLastLowestMassFirst(t *testing.T) {
	stored := map[string]*IPRecord{}
	var want []string
	for verdicts := 2; verdicts <= 12; verdicts++ {
		ip := fmt.Sprintf("198.51.100.%d", verdicts)
		stored[ip] = storedSpam(ip, float64(verdicts), 0, mailNow)
		stored[ip].Mail.Spam = verdicts
		if verdicts > 3 {
			want = append(want, ip)
		}
	}
	db := NewForTest(stored)
	db.SetMailBudget(10)

	// The twelfth record is the only one with a single verdict: it goes, then
	// the two of the lowest levels.
	report := db.RecordMailVerdict(thinIP(0), true, mailNow)

	if report == nil || report.Dropped != 3 {
		t.Fatalf("report = %+v, want 3 dropped", report)
	}
	slices.Sort(want)
	if got := recordKeys(db); !slices.Equal(got, want) {
		t.Errorf("records after the pass = %v, want %v", got, want)
	}
}

// Each budget drops one record more than the one before, in eviction order:
// lowest level first, inside a level the most crowded network first, then
// the lowest mass. The /16 of 198.51.100.0/24 holds six records, that of
// 203.0.113.0/24 five and that of 192.0.2.0/24 four.
func TestEvictionWeighsMassAtPassTime(t *testing.T) {
	const (
		created  = "192.0.2.1"     // one fresh verdict: mass 1, level 1
		twoWeeks = "192.0.2.2"     // one verdict, 4 two weeks ago: mass exactly 1, level 1
		exactTwo = "203.0.113.1"   // two fresh verdicts: mass exactly 2, level 2
		oldTwo   = "192.0.2.3"     // two verdicts 8 days ago: mass 0.91, level 2 all the same
		undated  = "203.0.113.2"   // 2.5 with no clock: keeps its weight, level 3
		withHam  = "203.0.113.3"   // 1.9 spam and 0.9 ham: mass 2.8, level 3
		oneWeek  = "203.0.113.4"   // 6 one week ago: mass 3, level 3
		lone     = "192.0.2.4"     // mass 2.1, level 3, in the least crowded network
		fresh    = "203.0.113.5"   // 4 now: level 4
		heavy    = "198.51.100.%d" // 10 each, level 10, in the most crowded network
	)
	evidence := func(spam, ham int, spamMass, hamMass float64, massAt time.Time) *IPRecord {
		return &IPRecord{LastSeen: mailNow, Mail: &MailEvidence{Spam: spam, Ham: ham, SpamMass: spamMass, HamMass: hamMass, MassAt: massAt}}
	}
	fixture := func() map[string]*IPRecord {
		stored := map[string]*IPRecord{
			twoWeeks: evidence(1, 0, 4, 0, mailNow.Add(-14*day)),
			exactTwo: evidence(2, 0, 2, 0, mailNow),
			oldTwo:   evidence(2, 0, 2, 0, mailNow.Add(-8*day)),
			undated:  evidence(3, 0, 2.5, 0, time.Time{}),
			withHam:  evidence(2, 1, 1.9, 0.9, mailNow),
			oneWeek:  evidence(6, 0, 6, 0, mailNow.Add(-7*day)),
			lone:     evidence(3, 0, 2.1, 0, mailNow),
			fresh:    evidence(4, 0, 4, 0, mailNow),
		}
		for n := range 6 {
			stored[fmt.Sprintf(heavy, n+1)] = evidence(10, 0, 10, 0, mailNow)
		}
		return stored
	}
	order := []string{twoWeeks, created, exactTwo, oldTwo, undated, withHam, oneWeek, lone, fresh, fmt.Sprintf(heavy, 1)}
	for _, budget := range []int{14, 13, 12, 11, 9, 8, 7, 6} {
		stored := fixture()
		db := NewForTest(stored)
		db.SetMailBudget(budget)
		drop := len(stored) + 1 - budget*9/10

		report := db.RecordMailVerdict(created, true, mailNow)

		if report == nil || report.Dropped != drop {
			t.Fatalf("budget %d: report = %+v, want %d dropped", budget, report, drop)
		}
		for n, key := range order {
			if _, ok := db.records[key]; ok != (n >= drop) {
				t.Errorf("budget %d: %s kept = %v, want %v", budget, key, ok, n >= drop)
			}
		}
		for key, rec := range db.records {
			if *rec.Mail != *stored[key].Mail {
				t.Errorf("budget %d: the pass changed the evidence of %s: %+v", budget, key, rec.Mail)
			}
		}
	}
}

// Every protected record has one spam verdict in a crowded /16, so it would
// go first if the pass looked at it.
func TestEvictionSparesRecordsThatAreNotMailOnly(t *testing.T) {
	stored := map[string]*IPRecord{}
	var protected []string
	for n := range 100 {
		ip := fmt.Sprintf("192.0.2.%d", n+1)
		protected = append(protected, ip)
		if n >= 67 {
			stored[ip] = storedSpam(ip, 1, 0, mailNow)
			stored[ip].Mail.AuthAttacks, stored[ip].Mail.LastAuthAttack = 1, mailNow.Add(-10*day)
		}
	}
	db := NewForTest(stored)
	db.SetMailBudget(100)
	for n, ip := range protected[:67] {
		db.RecordMailVerdict(ip, true, mailNow)
		if n < 34 {
			db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: ip, Timestamp: mailNow, Message: "x"})
		} else {
			db.MarkBlocked(ip)
		}
	}

	var thin []string
	for n := range 100 {
		thin = append(thin, mailRecordKey(thinIP(n)))
		if ev := db.RecordMailVerdict(thinIP(n), true, mailNow); ev != nil {
			t.Fatalf("eviction at %d mail-only records: %+v", n+1, ev)
		}
	}
	if len(db.records) != 200 || db.mailEvicted != 0 {
		t.Fatalf("%d records, %d evicted at the budget, want 200 and 0", len(db.records), db.mailEvicted)
	}

	report := db.RecordMailVerdict(thinIP(100), true, mailNow)

	thin = append(thin, mailRecordKey(thinIP(100)))
	slices.Sort(thin)
	if want := (Eviction{Dropped: 11, Network: "2001:db8:100::/48", NetworkRecords: 1}); report == nil || *report != want {
		t.Fatalf("report = %+v, want %+v", report, want)
	}
	want := append(slices.Clone(thin[11:]), protected...)
	slices.Sort(want)
	if got := recordKeys(db); !slices.Equal(got, want) {
		t.Errorf("records after the pass = %v, want %v", got, want)
	}
}

// Budget 10: the eleventh record starts the first pass, then every second one.
func TestEvictionReportOncePerDay(t *testing.T) {
	db := NewForTest(nil)
	db.SetMailBudget(10)
	next := 0
	create := func(at time.Time) *Eviction {
		next++
		return db.RecordMailVerdict(thinIP(next), true, at)
	}
	// The second new record is the one over the budget.
	pass := func(at time.Time) *Eviction {
		t.Helper()
		if ev := create(at); ev != nil {
			t.Fatalf("report from a call that ran no pass: %+v", ev)
		}
		return create(at)
	}
	for range 9 {
		create(mailNow)
	}

	if ev := pass(mailNow); ev == nil || ev.Dropped != 2 {
		t.Fatalf("first pass reported %+v, want 2 dropped", ev)
	}
	for _, age := range []time.Duration{time.Hour, 23 * time.Hour, day - time.Nanosecond} {
		if ev := pass(mailNow.Add(age)); ev != nil {
			t.Fatalf("pass %v after the report reported %+v", age, ev)
		}
	}
	// Two records in one /48 give this pass network figures of its own.
	db.RecordMailVerdict("2001:db8:7:1::1", true, mailNow.Add(day))
	ev := db.RecordMailVerdict("2001:db8:7:2::1", true, mailNow.Add(day))
	if want := (Eviction{Dropped: 8, Network: "2001:db8:7::/48", NetworkRecords: 2}); ev == nil || *ev != want {
		t.Fatalf("pass 24 hours after the report reported %+v, want %+v", ev, want)
	}
	if ev := pass(mailNow.Add(47 * time.Hour)); ev != nil {
		t.Fatalf("pass 23 hours after the second report reported %+v", ev)
	}
	if ev := pass(mailNow.Add(2 * day)); ev == nil || ev.Dropped != 4 {
		t.Fatalf("pass 24 hours after the second report reported %+v, want 4 dropped", ev)
	}
	if got := db.computeStats().MailEvicted; got != 14 {
		t.Errorf("MailEvicted = %d, want 14", got)
	}
}

// Budget 10, as above. A flood that stops must not leave its last drops
// unreported.
func TestPendingEvictionReportedAfterADay(t *testing.T) {
	db := NewForTest(nil)
	db.SetMailBudget(10)
	if ev := db.PendingEviction(mailNow); ev != nil {
		t.Fatalf("report before any drop: %+v", ev)
	}
	for n := range 10 {
		db.RecordMailVerdict(thinIP(n), true, mailNow)
	}
	if ev := db.RecordMailVerdict(thinIP(10), true, mailNow); ev == nil || ev.Dropped != 2 {
		t.Fatalf("first pass reported %+v, want 2 dropped", ev)
	}
	if ev := db.PendingEviction(mailNow.Add(day)); ev != nil {
		t.Fatalf("report with nothing pending: %+v", ev)
	}

	// Two more passes inside the day. The last one has network figures of its
	// own: two records in one /48.
	for n, ip := range []string{thinIP(11), thinIP(12), "2001:db8:7:1::1", "2001:db8:7:2::1"} {
		if ev := db.RecordMailVerdict(ip, true, mailNow.Add(time.Duration(n+1)*time.Minute)); ev != nil {
			t.Fatalf("verdict %d inside the day reported %+v", n, ev)
		}
	}
	if got := db.computeStats().MailEvicted; got != 6 {
		t.Fatalf("MailEvicted = %d, want 6 after three passes", got)
	}
	for _, age := range []time.Duration{time.Hour, day - time.Nanosecond} {
		if ev := db.PendingEviction(mailNow.Add(age)); ev != nil {
			t.Fatalf("pending report %v after the last one: %+v", age, ev)
		}
	}

	ev := db.PendingEviction(mailNow.Add(day))
	if want := (Eviction{Dropped: 4, Network: "2001:db8:7::/48", NetworkRecords: 2}); ev == nil || *ev != want {
		t.Fatalf("pending report a day after the last one = %+v, want %+v", ev, want)
	}
	for _, age := range []time.Duration{day, 3 * day} {
		if ev := db.PendingEviction(mailNow.Add(age)); ev != nil {
			t.Fatalf("drops reported twice, %v after the first report: %+v", age, ev)
		}
	}
	if got := db.computeStats().MailEvicted; got != 6 {
		t.Errorf("MailEvicted = %d, want 6: a report drops nothing", got)
	}
}

// Both kinds of report share one clock, or the same day would get two.
func TestPendingEvictionRestartsReportWindow(t *testing.T) {
	db := NewForTest(nil)
	db.SetMailBudget(10)
	next := 0
	// Every second new record is over the budget and starts a pass.
	pass := func(at time.Time) *Eviction {
		t.Helper()
		for range 2 {
			next++
			if ev := db.RecordMailVerdict(thinIP(next), true, at); ev != nil {
				return ev
			}
		}
		return nil
	}
	for range 9 {
		next++
		db.RecordMailVerdict(thinIP(next), true, mailNow)
	}
	if ev := pass(mailNow); ev == nil || ev.Dropped != 2 {
		t.Fatalf("first pass reported %+v, want 2 dropped", ev)
	}
	if ev := pass(mailNow.Add(time.Hour)); ev != nil {
		t.Fatalf("pass inside the day reported %+v", ev)
	}
	reported := mailNow.Add(day + 6*time.Hour)
	if ev := db.PendingEviction(reported); ev == nil || ev.Dropped != 2 {
		t.Fatalf("pending report = %+v, want 2 dropped", ev)
	}

	// More than a day after the first report, less than a day after the second.
	if ev := pass(reported.Add(day - time.Nanosecond)); ev != nil {
		t.Fatalf("pass inside a day of the pending report reported %+v", ev)
	}
	if ev := pass(reported.Add(day)); ev == nil || ev.Dropped != 4 {
		t.Fatalf("pass a day after the pending report reported %+v, want 4 dropped", ev)
	}
}

func TestEvictedRecordsAreDeletedFromStore(t *testing.T) {
	for _, backend := range []string{"json", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "bbolt" {
				_, cleanup := setupBboltStore(t)
				t.Cleanup(cleanup)
			}
			db := newTestDB(t)
			db.SetMailBudget(10)
			var keys []string
			for n := range 11 {
				if n == 10 {
					// The evicted records must reach the store first.
					if err := db.Flush(); err != nil {
						t.Fatal(err)
					}
				}
				keys = append(keys, mailRecordKey(thinIP(n)))
				db.RecordMailVerdict(thinIP(n), true, mailNow)
			}

			evicted, kept := keys[:2], keys[2:]
			for _, key := range evicted {
				if _, ok := db.deletedIPs[key]; !ok {
					t.Errorf("evicted %s is not marked deleted", key)
				}
			}
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			loaded := NewForTest(nil)
			loaded.dbPath = db.dbPath
			loaded.load()
			if got := recordKeys(loaded); !slices.Equal(got, kept) {
				t.Errorf("stored records = %v, want %v", got, kept)
			}
		})
	}
}

func TestMailOnlyCountRecountedOnLoadAndPrune(t *testing.T) {
	const spamOnly, withFinding, faded, bare = "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"
	for _, backend := range []string{"json", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "bbolt" {
				_, cleanup := setupBboltStore(t)
				t.Cleanup(cleanup)
			}
			now := time.Now()
			db := newTestDB(t)
			finding := func(ip string) {
				db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: ip, Timestamp: now, Message: "x"})
			}
			check := func(when string, count, truth int) {
				t.Helper()
				if got := mailOnlyAt(db, now); db.mailOnlyCount != count || got != truth {
					t.Fatalf("%s: count = %d with %d mail-only records, want %d and %d", when, db.mailOnlyCount, got, count, truth)
				}
			}

			for _, ip := range []string{spamOnly, withFinding, thinIP(0), thinIP(1)} {
				db.RecordMailVerdict(ip, true, now)
			}
			db.RecordMailVerdict(faded, true, now.Add(-47*day))
			// More verdicts about a counted record add nothing.
			db.RecordMailVerdict(spamOnly, true, now)
			db.RecordMailVerdict(spamOnly, false, now)
			check("five new records", 5, 5)
			finding(withFinding)
			check("a finding on one of them", 4, 4)
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}

			loaded := NewForTest(nil)
			loaded.dbPath = db.dbPath
			loaded.load()
			if len(loaded.records) != 5 || loaded.mailOnlyCount != 4 {
				t.Errorf("%d records loaded, count = %d, want 5 and 4", len(loaded.records), loaded.mailOnlyCount)
			}
			if got := NewForTest(db.records).mailOnlyCount; got != 4 {
				t.Errorf("count of a test database = %d, want 4", got)
			}

			db.pruneExpiredAt(now)
			check("prune", 3, 3)

			// A stored record with no mail section joins the class without being created.
			db.records[bare] = &IPRecord{IP: bare, LastSeen: now}
			db.RecordMailVerdict(bare, true, now)
			check("a verdict on a bare record", 4, 4)

			db.SetMailBudget(4)
			finding(spamOnly)
			check("a finding at the budget", 3, 3)
			if ev := db.RecordMailVerdict(thinIP(2), true, now); ev != nil {
				t.Fatalf("a new record at the budget reported %+v", ev)
			}
			check("a new record at the budget", 4, 4)

			// A removal leaves the count one too high; the pass it starts finds the budget kept.
			db.RemoveIP(mailRecordKey(thinIP(0)))
			check("a removal", 4, 3)
			if ev := db.RecordMailVerdict(thinIP(3), true, now); ev != nil {
				t.Fatalf("pass at the budget reported %+v", ev)
			}
			check("the pass", 4, 4)
			if len(db.records) != 6 || db.mailEvicted != 0 {
				t.Errorf("%d records, %d evicted after the pass, want 6 and 0", len(db.records), db.mailEvicted)
			}
		})
	}
}

func TestFindingOrBlockOnMailOnlyRecordKeepsCountExact(t *testing.T) {
	const found, blocked, kept, network, fresh = "192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8:1:2::1", "192.0.2.4"
	db := NewForTest(nil)
	finding := func(ip string) {
		db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: ip, Timestamp: mailNow, Message: "x"})
	}
	check := func(when string, want int) {
		t.Helper()
		if got := mailOnlyAt(db, mailNow); db.mailOnlyCount != want || got != want {
			t.Fatalf("%s: count = %d with %d mail-only records, want %d", when, db.mailOnlyCount, got, want)
		}
	}
	for _, ip := range []string{found, blocked, kept, network} {
		db.RecordMailVerdict(ip, true, mailNow)
	}
	check("four new records", 4)

	finding(found)
	check("a finding on a mail-only record", 3)
	db.MarkBlocked(blocked)
	check("a block on a mail-only record", 2)

	// None of these takes a record out of the class.
	finding(found)
	check("a second finding", 2)
	db.MarkBlocked(blocked)
	check("a second block", 2)
	db.MarkBlocked(found)
	check("a block on a record with a finding", 2)
	finding(blocked)
	check("a finding on a blocked record", 2)
	finding(fresh)
	check("a finding from a new address", 2)
	db.MarkBlocked("192.0.2.5")
	check("a block on an unknown address", 2)
	// Findings are per address: the /64 record stays mail-only.
	finding(network)
	db.MarkBlocked(network)
	check("a finding and a block inside a /64 record", 2)
}

// A finding takes one record out of the class and the next new sender takes
// its place, so the count never passes the budget and no pass has to run.
func TestFindingAtBudgetDoesNotForceAPass(t *testing.T) {
	const budget = 100
	db := NewForTest(nil)
	db.SetMailBudget(budget)
	for n := range budget {
		db.RecordMailVerdict(fmt.Sprintf("192.0.2.%d", n+1), true, mailNow)
	}
	check := func(when string, n, want int) {
		t.Helper()
		if got := mailOnlyAt(db, mailNow); db.mailOnlyCount != want || got != want {
			t.Fatalf("pair %d, %s: count = %d with %d mail-only records, want %d", n, when, db.mailOnlyCount, got, want)
		}
	}
	check("the budget filled", 0, budget)

	for n := range 50 {
		db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: fmt.Sprintf("192.0.2.%d", n+1), Timestamp: mailNow, Message: "x"})
		// Only a new record at a count of the budget or more starts a pass.
		check("the finding", n, budget-1)
		if ev := db.RecordMailVerdict(fmt.Sprintf("198.51.100.%d", n+1), true, mailNow); ev != nil {
			t.Fatalf("pair %d reported an eviction: %+v", n, ev)
		}
		check("the new sender", n, budget)
	}
	if len(db.records) != budget+50 || len(db.deletedIPs) != 0 || db.mailEvicted != 0 {
		t.Errorf("%d records, %d deleted, %d evicted, want %d, 0, 0", len(db.records), len(db.deletedIPs), db.mailEvicted, budget+50)
	}
}

// A pass always trims to nine tenths of the budget. Senders of one message
// each reach records with two verdicts only when those alone fill more.
func TestTrimReachesMultiVerdictRecordsOnlyAboveNineTenths(t *testing.T) {
	// Sender n has two verdicts n hours old, so a higher n is the weaker record.
	twoVerdicts := func(db *DB, senders int) []string {
		var keys []string
		for n := range senders {
			ip := fmt.Sprintf("2001:db8:%x:1::1", 0x1000+n)
			keys = append(keys, mailRecordKey(ip))
			for range 2 {
				db.RecordMailVerdict(ip, true, mailNow.Add(-time.Duration(n)*time.Hour))
			}
		}
		return keys
	}
	present := func(db *DB, keys []string) int {
		n := 0
		for _, key := range keys {
			if _, ok := db.records[key]; ok {
				n++
			}
		}
		return n
	}

	t.Run("under nine tenths", func(t *testing.T) {
		db := NewForTest(nil)
		db.SetMailBudget(100)
		strong := twoVerdicts(db, 89)
		for n := range 200 {
			db.RecordMailVerdict(thinIP(n), true, mailNow)
			if got := present(db, strong); got != 89 {
				t.Fatalf("one-message sender %d left %d of 89 two-verdict records", n, got)
			}
		}
		// A pass at sender 12 and at every eleventh after it.
		if db.mailEvicted != 198 || len(db.records) != 91 {
			t.Errorf("%d evicted, %d records left, want 198 and 91", db.mailEvicted, len(db.records))
		}
	})

	t.Run("above nine tenths", func(t *testing.T) {
		db := NewForTest(nil)
		db.SetMailBudget(100)
		strong := twoVerdicts(db, 95)
		for n := range 6 {
			db.RecordMailVerdict(thinIP(n), true, mailNow)
		}
		// The pass drops the six single verdicts, then the five oldest pairs.
		if got := present(db, strong[:90]); got != 90 || present(db, strong[90:]) != 0 || len(db.records) != 90 {
			t.Fatalf("%d of the 90 stronger and %d of the 5 weakest two-verdict records left, %d records in all, want 90, 0 and 90",
				got, present(db, strong[90:]), len(db.records))
		}
		for n := range 100 {
			db.RecordMailVerdict(thinIP(6+n), true, mailNow)
			if got := present(db, strong[:90]); got != 90 {
				t.Fatalf("one-message sender %d after the trim left %d of 90 two-verdict records", n, got)
			}
		}
	})
}

// No mix of verdicts, findings, blocks, forgets and prunes leaves the count
// below the true number, or the true number above the budget after a verdict.
func TestMailOnlyCountNeverBelowTruth(t *testing.T) {
	const budget = 20
	r := rand.New(rand.NewSource(1))
	pool := make([]string, 0, 120)
	stored := map[string]*IPRecord{}
	for n := range 40 {
		v4 := fmt.Sprintf("203.0.113.%d", n+1)
		pool = append(pool, v4, fmt.Sprintf("2001:db8:%x:%x::1", n%4, n), thinIP(n))
		if n%2 == 0 {
			stored[v4] = &IPRecord{IP: v4, LastSeen: mailNow}
		}
	}
	_, forgotten, err := net.ParseCIDR("2001:db8:100::/45")
	if err != nil {
		t.Fatal(err)
	}
	db := NewForTest(stored)
	db.SetMailBudget(budget)
	at := mailNow
	for step := range 5000 {
		at = at.Add(time.Duration(r.Intn(3600)) * time.Second)
		ip := pool[r.Intn(len(pool))]
		switch op := r.Intn(20); {
		case op < 12:
			db.RecordMailVerdict(ip, op < 9, at)
			if got := mailOnlyAt(db, at); got > budget {
				t.Fatalf("step %d: %d mail-only records, budget %d", step, got, budget)
			}
		case op < 14:
			db.RecordFinding(alert.Finding{Check: "smtp_bruteforce", SourceIP: ip, Timestamp: at, Message: "x"})
		case op < 16:
			db.MarkBlocked(ip)
		case op < 17:
			db.RemoveIP(mailRecordKey(ip))
		case op < 18:
			db.ForgetIP(net.ParseIP(ip))
		case op < 19:
			db.ForgetNetworks([]*net.IPNet{forgotten})
		default:
			db.pruneExpiredAt(at)
		}
		if got := mailOnlyAt(db, at); db.mailOnlyCount < got {
			t.Fatalf("step %d: count %d below the %d mail-only records", step, db.mailOnlyCount, got)
		}
	}
	if db.mailEvicted == 0 {
		t.Fatal("no pass evicted anything")
	}
}

func TestBudgetZeroNeverEvicts(t *testing.T) {
	for _, budget := range []int{0, -1} {
		db := NewForTest(nil)
		db.SetMailBudget(budget)
		for n := range 300 {
			if ev := db.RecordMailVerdict(thinIP(n), true, mailNow); ev != nil {
				t.Fatalf("budget %d: verdict %d reported %+v", budget, n, ev)
			}
		}
		if len(db.records) != 300 || db.mailEvicted != 0 {
			t.Errorf("budget %d: %d records, %d evicted, want 300 and 0", budget, len(db.records), db.mailEvicted)
		}
	}
}

// One pass over 200,000 mail-only records in 65,536 networks.
func BenchmarkEvictionPass(b *testing.B) {
	const records = 200_000
	for range b.N {
		b.StopTimer()
		db := NewForTest(nil)
		for i := range records {
			db.RecordMailVerdict(fmt.Sprintf("2001:db8:%x:%x::1", i&0xffff, i>>16), true, mailNow)
		}
		db.SetMailBudget(records)
		b.StartTimer()
		ev := db.RecordMailVerdict("2001:db8:0:ffff::1", true, mailNow)
		if ev == nil || ev.Dropped != records/10+1 {
			b.Fatalf("pass reported %+v", ev)
		}
	}
}
