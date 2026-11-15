package attackdb

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// Init owns a process singleton and a saver goroutine. Run its tests in a
// fresh process rather than resetting a sync.Once or stopping another DB.
func runInitTest(t *testing.T, name string, env ...string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^"+name+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CSM_TEST_INIT="+name)
	cmd.Env = append(cmd.Env, env...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Init subprocess: %v\n%s", err, output)
	}
}

func TestInitBudgetTestPreservesSingleton(t *testing.T) {
	if os.Getenv("CSM_TEST_INIT") != t.Name() {
		runInitTest(t, t.Name())
		return
	}
	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sdb.Close() }()
	store.SetGlobal(sdb)
	db := Init(t.TempDir())
	t.Run("budget", TestInitAppliesDefaultMailBudget)
	if Global() != db || store.Global() != sdb {
		t.Fatal("budget test replaced a package singleton")
	}
	select {
	case <-db.stopCh:
		t.Fatal("budget test stopped the existing database")
	default:
		defer db.Stop()
	}
	if got := Init(t.TempDir()); got != db {
		t.Fatal("budget test reset the existing Init guard")
	}
}

// Exercise the default itself through both production load paths. A fresh
// process for each phase also proves persisted deletions survive a restart.
func TestInitMailBudgetLifecycle(t *testing.T) {
	if os.Getenv("CSM_TEST_INIT") != t.Name() {
		for _, backend := range []string{"json", "bbolt"} {
			if backend == "bbolt" && testing.Short() {
				continue // one store transaction per record: about a minute
			}
			dir := t.TempDir()
			now := time.Now()
			records := make(map[string]*IPRecord)
			for n := range DefaultMailBudget + 1 {
				key := mailRecordKey(thinIP(n))
				if n == 1 {
					// Legacy per-address IPv6 evidence still counts.
					key = thinIP(n)
				}
				records[key] = &IPRecord{IP: key, FirstSeen: now, LastSeen: now,
					Mail: &MailEvidence{Spam: 1, SpamMass: 1, MassAt: now, LastSpam: now}}
			}
			for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"} {
				records[ip] = &IPRecord{IP: ip, FirstSeen: now, LastSeen: now,
					Mail: &MailEvidence{Spam: 1, SpamMass: 1, MassAt: now}}
			}
			records["192.0.2.1"].EventCount = 1
			records["192.0.2.1"].AttackCounts = map[AttackType]int{AttackBruteForce: 1}
			records["192.0.2.2"].AutoBlocked = true
			records["192.0.2.3"].Mail.AuthAttacks = 1
			records["192.0.2.3"].Mail.LastAuthAttack = now
			records["192.0.2.4"].LastSeen = now.Add(-91 * day)
			data, err := json.Marshal(records)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "attack_db")
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, recordsFile), data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, phase := range []string{"upgrade", "restart"} {
				runInitTest(t, t.Name(), "CSM_TEST_INIT_BACKEND="+backend,
					"CSM_TEST_INIT_DIR="+dir, "CSM_TEST_INIT_PHASE="+phase)
			}
		}
		return
	}
	dir := os.Getenv("CSM_TEST_INIT_DIR")
	if os.Getenv("CSM_TEST_INIT_BACKEND") == "bbolt" {
		sdb, err := store.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sdb.Close() }()
		store.SetGlobal(sdb)
	}
	db := Init(dir)
	defer db.Stop()
	if db.mailBudget != DefaultMailBudget {
		t.Fatalf("budget = %d", db.mailBudget)
	}
	want := DefaultMailBudget + 1
	restart := os.Getenv("CSM_TEST_INIT_PHASE") == "restart"
	if restart {
		want = DefaultMailBudget * 9 / 10
	}
	stats := db.computeStats()
	if stats.MailOnlyIPs != want || stats.TotalIPs != want+3 || stats.MailEvicted != 0 {
		t.Fatalf("startup: mail-only=%d total=%d evicted=%d, want %d, %d, 0",
			stats.MailOnlyIPs, stats.TotalIPs, stats.MailEvicted, want, want+3)
	}
	if db.records["192.0.2.4"] != nil {
		t.Fatal("startup kept expired evidence")
	}
	if db.PendingEviction(time.Now()) != nil {
		t.Fatal("startup reported an eviction")
	}
	if ev := db.RecordMailVerdict("203.0.113.1", false, time.Now()); ev != nil {
		t.Fatal("untracked ham triggered eviction")
	}
	if got := db.TotalIPs(); got != want+3 {
		t.Fatalf("untracked ham changed total to %d", got)
	}
	if restart {
		rec := db.records[mailRecordKey(thinIP(0))]
		if rec == nil || rec.Mail.Spam != 1 || rec.Mail.Ham != 1 {
			t.Fatalf("restart lost the verdict that triggered eviction: %+v", rec)
		}
	}
	ev := db.RecordMailVerdict(thinIP(0), false, time.Now())
	dropped := DefaultMailBudget + 1 - DefaultMailBudget*9/10
	if restart {
		dropped = 0
		if ev != nil {
			t.Fatalf("restart evicted under budget: %+v", ev)
		}
	} else if ev == nil || ev.Dropped != dropped {
		t.Fatalf("first recorded verdict reported %+v, want %d drops", ev, dropped)
	}
	stats = db.computeStats()
	if stats.MailOnlyIPs != DefaultMailBudget*9/10 || stats.TotalIPs != DefaultMailBudget*9/10+3 || stats.MailEvicted != dropped {
		t.Fatalf("after verdict: mail-only=%d total=%d evicted=%d", stats.MailOnlyIPs, stats.TotalIPs, stats.MailEvicted)
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if db.records[ip] == nil {
			t.Fatalf("evicted protected record %s", ip)
		}
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
}
