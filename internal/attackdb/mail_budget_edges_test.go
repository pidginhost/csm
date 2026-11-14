package attackdb

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestBudgetCountsAgingAuthEvidence(t *testing.T) {
	now := time.Now()
	const ip = "192.0.2.1"
	for _, op := range []string{"verdict", "finding", "block", "prune", "backwards"} {
		t.Run(op, func(t *testing.T) {
			rec := storedSpam(ip, 20, 0, now)
			rec.Mail.AuthAttacks, rec.Mail.LastAuthAttack = 1, now
			if op == "block" {
				rec.Mail.LastAuthAttack = now.Add(-31 * day)
			}
			db := NewForTest(map[string]*IPRecord{ip: rec})
			db.SetMailBudget(1)
			at := now.Add(31 * day)
			switch op {
			case "verdict":
				// Expiration alone makes an existing record eligible, even without a new sender.
				db.RecordMailVerdict("198.51.100.1", true, now)
				db.RecordMailVerdict(ip, true, at)
			case "finding":
				db.RecordFinding(alert.Finding{Check: "smtp_bruteforce", SourceIP: ip, Timestamp: at})
			case "block":
				// A pass with an older verdict time must not uncount a later-eligible record.
				db.SetMailBudget(2)
				for n := range 3 {
					db.RecordMailVerdict(thinIP(n), true, now.Add(-2*day))
				}
				db.MarkBlocked(ip)
			case "prune":
				db.pruneExpiredAt(now)
				db.RecordMailVerdict("198.51.100.1", true, at)
			case "backwards":
				db.RecordFinding(alert.Finding{Check: "wp_login_bruteforce", SourceIP: ip, Timestamp: now.Add(-day)})
				at = now
			}
			if truth := mailOnlyAt(db, at); db.mailOnlyCount < truth {
				t.Fatalf("count %d below %d eligible records", db.mailOnlyCount, truth)
			}
			if truth := mailOnlyAt(db, at); truth > db.mailBudget {
				t.Fatalf("%d eligible records exceed budget %d", truth, db.mailBudget)
			}
		})
	}
}

func TestMailLevelLargeVerdictCounts(t *testing.T) {
	m := &MailEvidence{Spam: math.MaxInt, Ham: 1, SpamMass: 0.2, HamMass: 0.1}
	if got := mailLevel(m); got != 2 {
		t.Fatalf("level = %v, want 2", got)
	}
}

func TestBudgetSmallAndCorruptKeys(t *testing.T) {
	for budget := 1; budget <= 9; budget++ {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			db := NewForTest(map[string]*IPRecord{"invalid": storedSpam("invalid", 1, 0, mailNow)})
			db.SetMailBudget(budget)
			for n := range budget {
				db.RecordMailVerdict(thinIP(n), true, mailNow)
			}
			if got, want := len(db.records), budget*9/10; got != want {
				t.Fatalf("%d records left, want %d", got, want)
			}
			if db.mailEvicted != 2 {
				t.Fatalf("%d evicted, want 2", db.mailEvicted)
			}
		})
	}
}

func TestEvictionReportBackwardsTime(t *testing.T) {
	db := NewForTest(nil)
	db.SetMailBudget(1)
	pass := func(at time.Time) *Eviction {
		db.RecordMailVerdict("192.0.2.1", true, at)
		return db.RecordMailVerdict("198.51.100.1", true, at)
	}
	if ev := pass(mailNow); ev == nil {
		t.Fatal("missing first report")
	}
	if ev := pass(mailNow.Add(-day)); ev != nil {
		t.Fatalf("backdated report: %+v", ev)
	}
	if ev := pass(mailNow.Add(day - time.Nanosecond)); ev != nil {
		t.Fatalf("early report: %+v", ev)
	}
	if ev := pass(mailNow.Add(day)); ev == nil || ev.Dropped != 6 {
		t.Fatalf("report = %+v, want 6 dropped", ev)
	}
}

// Network cardinality must not add one heap allocation per record or network.
func TestEvictionPassAllocations(t *testing.T) {
	const count = 2000
	stored := make(map[string]*IPRecord, count)
	for n := range count {
		key := mailRecordKey(thinIP(n))
		stored[key] = storedSpam(key, 1, 0, mailNow)
	}
	db := NewForTest(stored)
	db.SetMailBudget(count - 1)
	allocations := testing.AllocsPerRun(3, func() {
		for key, rec := range stored {
			db.records[key] = rec
		}
		db.mailOnlyCount = count
		db.mailEvictReport = time.Time{}
		ev := db.evictMailLocked(mailNow)
		if ev == nil || ev.Dropped != count-(count-1)*9/10 {
			t.Fatalf("unexpected eviction: %+v", ev)
		}
	})
	// Allow map growth and report storage, but not per-record allocations.
	if allocations >= count/2 {
		t.Fatalf("%.0f allocations for %d records", allocations, count)
	}
}

func TestEvictionFirstReportBeforeZeroClock(t *testing.T) {
	db := NewForTest(nil)
	db.SetMailBudget(1)
	at := time.Time{}.Add(-time.Hour)
	db.RecordMailVerdict("192.0.2.1", true, at)
	if ev := db.RecordMailVerdict("198.51.100.1", true, at); ev == nil || ev.Dropped != 2 {
		t.Fatalf("first report = %+v, want 2 dropped", ev)
	}
}

func TestBudgetAuthIndexAcrossMutations(t *testing.T) {
	now := time.Now()
	stored := make(map[string]*IPRecord)
	pool := make([]string, 60)
	for n := range pool {
		ip := fmt.Sprintf("192.0.2.%d", n+1)
		pool[n] = ip
		rec := storedSpam(ip, 20, 0, now)
		// Repeated timestamps must remove only one matching entry.
		rec.Mail.AuthAttacks, rec.Mail.LastAuthAttack = 1, now.Add(-time.Duration(n%3)*day)
		stored[ip] = rec
	}
	db := NewForTest(stored)
	db.SetMailBudget(20)
	random := rand.New(rand.NewSource(2))
	for step := range 2000 {
		at := now.Add(time.Duration(random.Intn(35)) * day)
		ip := pool[random.Intn(len(pool))]
		switch op := random.Intn(6); op {
		case 0:
			db.RecordFinding(alert.Finding{Check: "smtp_bruteforce", SourceIP: ip, Timestamp: at})
		case 1:
			db.MarkBlocked(ip)
		case 2:
			db.RemoveIP(ip)
		case 3:
			db.ForgetIP(net.ParseIP(ip))
		case 4:
			db.pruneExpiredAt(at)
		case 5:
			protected := make(map[string]bool)
			for key, rec := range db.records {
				protected[key] = !mailOnly(rec, at)
			}
			db.RecordMailVerdict(ip, true, at)
			for key, keep := range protected {
				if _, ok := db.records[key]; keep && !ok {
					t.Fatalf("step %d: evicted protected %s", step, key)
				}
			}
			if got := mailOnlyAt(db, at); got > db.mailBudget {
				t.Fatalf("step %d: %d eligible, budget %d", step, got, db.mailBudget)
			}
		}
		for _, checkAt := range []time.Time{now.Add(-day), now, now.Add(31 * day)} {
			truth := mailOnlyAt(db, checkAt)
			if db.mailOnlyCount < truth || db.mailCountAtLocked(checkAt) < truth {
				t.Fatalf("step %d: total %d, eligible %d, truth %d at %s", step, db.mailOnlyCount, db.mailCountAtLocked(checkAt), truth, checkAt)
			}
		}
	}
}

func TestLoadedBudgetCountsAgingAuthEvidence(t *testing.T) {
	for _, backend := range []string{"json", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "bbolt" {
				_, cleanup := setupBboltStore(t)
				t.Cleanup(cleanup)
			}
			now := time.Now()
			db := newTestDB(t)
			const ip = "192.0.2.1"
			rec := storedSpam(ip, 20, 0, now)
			rec.Mail.AuthAttacks, rec.Mail.LastAuthAttack = 1, now
			db.records[ip] = rec
			db.markDirtyLocked(ip)
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			loaded := NewForTest(nil)
			loaded.dbPath = db.dbPath
			loaded.load()
			loaded.SetMailBudget(1)
			loaded.RecordMailVerdict("198.51.100.1", true, now)
			if got := len(loaded.records); got != 2 {
				t.Fatalf("%d records before expiration, want 2", got)
			}
			if ev := loaded.RecordMailVerdict(ip, true, now.Add(31*day)); ev == nil || ev.Dropped != 2 {
				t.Fatalf("after expiration report = %+v, want 2 dropped", ev)
			}
			if loaded.mailOnlyCount != 0 || len(loaded.records) != 0 {
				t.Fatalf("count %d, records %d, want 0", loaded.mailOnlyCount, len(loaded.records))
			}
		})
	}
}

func TestProtectedAuthDoesNotForcePassPerVerdict(t *testing.T) {
	now := time.Now()
	stored := make(map[string]*IPRecord)
	for n := range 100 {
		ip := fmt.Sprintf("192.0.2.%d", n+1)
		rec := storedSpam(ip, 20, 0, now)
		rec.Mail.AuthAttacks, rec.Mail.LastAuthAttack = 1, now
		stored[ip] = rec
	}
	db := NewForTest(stored)
	db.SetMailBudget(100)
	for n := range 90 {
		db.RecordMailVerdict(thinIP(n), true, now)
	}
	if got := len(db.records); got != 190 {
		t.Fatalf("%d records, want 190", got)
	}
	// An operator removal leaves a stale count. Any full pass would recount it,
	// exposing unnecessary scans even when those scans evict nothing.
	before := db.mailOnlyCount
	db.RemoveIP("192.0.2.1")
	for n := range 50 {
		db.RecordMailVerdict(thinIP(n), true, now.Add(-time.Duration(n)*time.Minute))
		if db.mailOnlyCount != before {
			t.Fatalf("verdict %d triggered a recount", n)
		}
	}
	if db.mailEvicted != 0 || len(db.records) != 189 {
		t.Fatalf("%d evicted, %d records, want 0 and 189", db.mailEvicted, len(db.records))
	}
}
