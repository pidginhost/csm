package attackdb

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

func recordQueueStatus(t *testing.T, db *DB, now time.Time) queuehealth.Status {
	t.Helper()
	row, ok := db.QueueStatuses(now)["records"]
	if !ok {
		t.Fatal("changed-record persistence queue is missing")
	}
	if !row.CapacityUnavailable || row.Capacity != 0 {
		t.Fatalf("changed-record queue invented a fixed capacity: %+v", row)
	}
	return row
}

func TestAttackRecordQueueCoalescesCurrentIntent(t *testing.T) {
	for _, backend := range []string{"file", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			db := eventQueueFlatDB(t)
			if backend == "bbolt" {
				_, cleanup := setupBboltStore(t)
				t.Cleanup(cleanup)
			}
			for _, ip := range []string{"198.51.100.23", "198.51.100.23", "203.0.113.24"} {
				db.RecordFinding(findingFromIP(ip))
			}
			db.MarkBlocked("198.51.100.23")
			db.RemoveIP("198.51.100.23")
			db.RecordFinding(findingFromIP("198.51.100.23"))
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 2 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
				t.Fatalf("coalesced writes: %+v", s)
			}
			db.saveRecords()
			restored := NewForTest(nil)
			restored.dbPath = db.dbPath
			restored.load()
			if a := restored.LookupIP("198.51.100.23"); a == nil || a.EventCount != 1 {
				t.Fatalf("current record intent not saved: %+v", a)
			}
			if b := restored.LookupIP("203.0.113.24"); b == nil || b.EventCount != 1 {
				t.Fatalf("other record lost: %+v", b)
			}
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 {
				t.Fatalf("completed write ownership: %+v", s)
			}
			db.RemoveIP("203.0.113.24")
			db.RemoveIP("203.0.113.24")
			if removed := db.ForgetIP(net.ParseIP("198.51.100.23")); len(removed) != 1 {
				t.Fatalf("forgot %d, want 1", len(removed))
			}
			db.MarkBlocked("198.51.100.23")
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 2 || s.DroppedTotal != 0 {
				t.Fatalf("coalesced deletes: %+v", s)
			}
			db.saveRecords()
			restored = NewForTest(nil)
			restored.dbPath = db.dbPath
			restored.load()
			if n := restored.TotalIPs(); n != 0 {
				t.Fatalf("persisted deletions retained %d records", n)
			}
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 {
				t.Fatalf("completed delete ownership: %+v", s)
			}
		})
	}
}

func TestAttackRecordQueueRetriesWithoutInventingLoss(t *testing.T) {
	for _, backend := range []string{"file", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			db := eventQueueFlatDB(t)
			var storeDir string
			if backend == "bbolt" {
				var cleanup func()
				storeDir, cleanup = setupBboltStore(t)
				t.Cleanup(cleanup)
			}
			db.RecordFinding(findingFromIP("198.51.100.23"))
			db.RemoveIP("203.0.113.24")
			future := time.Now().Add(2 * time.Minute)
			before := recordQueueStatus(t, db, future)
			if before.Depth != 2 || before.Reason != "backlog_lag" {
				t.Fatalf("queued changes did not age: %+v", before)
			}
			target := filepath.Join(db.dbPath, recordsFile)
			if backend == "bbolt" {
				if err := store.Global().Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			}
			db.saveRecords()
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 2 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "degraded" || s.Reason != "retry_failed" {
				t.Fatalf("retained retry misreported: %+v", s)
			}
			if s := recordQueueStatus(t, db, future); s.LagSeconds != before.LagSeconds {
				t.Fatalf("retry reset age: before=%+v after=%+v", before, s)
			}
			db.saveRecords()
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 2 || s.InFlight != 0 || s.DroppedTotal != 0 {
				t.Fatalf("repeated failure inflated work: %+v", s)
			}
			if backend == "bbolt" {
				reopened, err := store.Open(storeDir)
				if err != nil {
					t.Fatal(err)
				}
				store.SetGlobal(reopened)
				t.Cleanup(func() { _ = reopened.Close() })
			} else {
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			}
			db.saveRecords()
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
				t.Fatalf("completed retry remained unhealthy: %+v", s)
			}
			restored := NewForTest(nil)
			restored.dbPath = db.dbPath
			restored.load()
			if got := restored.LookupIP("198.51.100.23"); got == nil || got.EventCount != 1 {
				t.Fatalf("retry lost queued record: %+v", got)
			}
			if got := restored.LookupIP("203.0.113.24"); got != nil {
				t.Fatalf("retry lost pending delete: %+v", got)
			}
		})
	}
}

func TestAttackRecordQueueMemoryOnlyHasNoPersistenceWork(t *testing.T) {
	_ = eventQueueFlatDB(t)
	db := NewForTest(nil)
	db.RecordFinding(findingFromIP("198.51.100.23"))
	db.RemoveIP("203.0.113.24")
	db.saveRecords()
	if s := recordQueueStatus(t, db, time.Now().Add(time.Hour)); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
		t.Fatalf("memory-only records invented persistence: %+v", s)
	}
}

func TestAttackRecordQueueConcurrentMutationKeepsNewWork(t *testing.T) {
	for _, backend := range []string{"file", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			db := eventQueueFlatDB(t)
			if backend == "bbolt" {
				_, cleanup := setupBboltStore(t)
				t.Cleanup(cleanup)
			}
			db.RecordFinding(findingFromIP("198.51.100.23"))
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(func() {
				unblock()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("record flush did not join")
				}
			})
			if backend == "bbolt" {
				db.saveRecord = func(sdb *store.DB, rec store.IPRecord) error { close(entered); <-release; return sdb.SaveIPRecord(rec) }
			} else {
				db.writeRecords = func(path string, data []byte) error { close(entered); <-release; return writeRecordFile(path, data) }
			}
			go func() { defer close(done); _ = db.Flush() }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("record writer did not start")
			}
			db.RecordFinding(findingFromIP("198.51.100.23"))
			db.RecordFinding(findingFromIP("203.0.113.24"))
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 2 || s.InFlight != 1 || s.DroppedTotal != 0 {
				t.Fatalf("concurrent mutation lost ownership: %+v", s)
			}
			if s := recordQueueStatus(t, db, time.Now().Add(2*time.Minute)); s.Status != "degraded" || s.LagBasis != "operation_progress" || s.ProcessingSeconds < 60 {
				t.Fatalf("blocked writer missing: %+v", s)
			}
			db.mu.Lock()
			read := make(chan queuehealth.Status, 1)
			go func() { read <- db.QueueStatuses(time.Now())["records"] }()
			select {
			case s := <-read:
				if s.Depth != 2 || s.InFlight != 1 {
					t.Errorf("locked snapshot: %+v", s)
				}
			case <-time.After(time.Second):
				t.Error("record health waited for state lock")
			}
			db.mu.Unlock()
			unblock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("record writer did not finish")
			}
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 2 || s.InFlight != 0 || s.DroppedTotal != 0 {
				t.Fatalf("old write consumed newer changes: %+v", s)
			}
			restored := NewForTest(nil)
			restored.dbPath = db.dbPath
			restored.load()
			if a := restored.LookupIP("198.51.100.23"); a == nil || a.EventCount != 1 || restored.TotalIPs() != 1 {
				t.Fatal("first flush did not persist exactly its snapshot")
			}
			db.saveRecord = nil
			db.writeRecords = nil
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			restored = NewForTest(nil)
			restored.dbPath = db.dbPath
			restored.load()
			if a := restored.LookupIP("198.51.100.23"); a == nil || a.EventCount != 2 {
				t.Fatalf("new mutation not persisted: %+v", a)
			}
			if b := restored.LookupIP("203.0.113.24"); b == nil || b.EventCount != 1 {
				t.Fatalf("new IP not persisted: %+v", b)
			}
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
				t.Fatalf("completed current writes: %+v", s)
			}
		})
	}
}

func TestAttackRecordQueueDeleteCoalescesDuringCommit(t *testing.T) {
	for _, backend := range []string{"file", "bbolt"} {
		for _, mutation := range []string{"delete_again", "readd"} {
			t.Run(backend+"/"+mutation, func(t *testing.T) {
				db := eventQueueFlatDB(t)
				if backend == "bbolt" {
					_, cleanup := setupBboltStore(t)
					t.Cleanup(cleanup)
				}
				db.RecordFinding(findingFromIP("198.51.100.23"))
				if err := db.Flush(); err != nil {
					t.Fatal(err)
				}
				db.RemoveIP("198.51.100.23")
				entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				t.Cleanup(func() {
					unblock()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("delete did not join")
					}
				})
				db.deleteRecord = func(sdb *store.DB, ip string) error { close(entered); <-release; return sdb.DeleteIPRecord(ip) }
				db.writeRecords = func(path string, data []byte) error { close(entered); <-release; return writeRecordFile(path, data) }
				go func() { defer close(done); _ = db.Flush() }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("delete did not start")
				}
				if s := recordQueueStatus(t, db, time.Now().Add(2*time.Minute)); s.Depth != 0 || s.InFlight != 1 || s.Reason != "processing_lag" {
					t.Fatalf("stalled delete not measured: %+v", s)
				}
				if mutation == "readd" {
					db.RecordFinding(findingFromIP("198.51.100.23"))
				} else {
					db.RemoveIP("198.51.100.23")
				}
				if s := recordQueueStatus(t, db, time.Now()); s.Depth != 1 || s.InFlight != 1 || s.DroppedTotal != 0 {
					t.Fatalf("concurrent delete intent missing: %+v", s)
				}
				unblock()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("delete did not finish")
				}
				wantDepth := 0
				if mutation == "readd" {
					wantDepth = 1
				}
				if s := recordQueueStatus(t, db, time.Now()); s.Depth != wantDepth || s.InFlight != 0 || s.DroppedTotal != 0 {
					t.Fatalf("delete settled wrong generation: %+v", s)
				}
				restored := NewForTest(nil)
				restored.dbPath = db.dbPath
				restored.load()
				if n := restored.TotalIPs(); n != 0 {
					t.Fatalf("first delete retained %d records", n)
				}
				db.deleteRecord = nil
				db.writeRecords = nil
				if err := db.Flush(); err != nil {
					t.Fatal(err)
				}
				restored = NewForTest(nil)
				restored.dbPath = db.dbPath
				restored.load()
				if n := restored.TotalIPs(); n != wantDepth {
					t.Fatalf("final persisted IPs=%d, want %d", n, wantDepth)
				}
				if mutation == "readd" {
					if rec := restored.LookupIP("198.51.100.23"); rec == nil || rec.EventCount != 1 {
						t.Fatal("re-added record contents not persisted")
					}
				}
				if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
					t.Fatalf("completed delete/re-add stayed active: %+v", s)
				}
			})
		}
	}
}

func TestAttackRecordQueueWriteProgressResetsStall(t *testing.T) {
	db := eventQueueFlatDB(t)
	_, cleanup := setupBboltStore(t)
	t.Cleanup(cleanup)
	for _, ip := range []string{"198.51.100.23", "203.0.113.24"} {
		db.RecordFinding(findingFromIP(ip))
	}
	entered := make(chan int, 2)
	first, second, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var firstOnce, secondOnce sync.Once
	unblock := func() { firstOnce.Do(func() { close(first) }); secondOnce.Do(func() { close(second) }) }
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("progress batch did not join")
		}
	})
	writes := 0
	db.saveRecord = func(sdb *store.DB, rec store.IPRecord) error {
		writes++
		entered <- writes
		if writes == 1 {
			<-first
		} else {
			<-second
		}
		return sdb.SaveIPRecord(rec)
	}
	go func() { defer close(done); _ = db.Flush() }()
	select {
	case n := <-entered:
		if n != 1 {
			t.Fatalf("first write=%d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first write did not start")
	}
	q := db.recordHealth()
	q.mu.Lock()
	q.active.progress = time.Now().Add(-2 * time.Minute)
	q.mu.Unlock()
	if s := recordQueueStatus(t, db, time.Now()); s.InFlight != 2 || s.Reason != "processing_lag" {
		t.Fatalf("stalled first write missing: %+v", s)
	}
	firstOnce.Do(func() { close(first) })
	select {
	case n := <-entered:
		if n != 2 {
			t.Fatalf("second write=%d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second write did not start")
	}
	if s := recordQueueStatus(t, db, time.Now()); s.InFlight != 2 || s.Depth != 0 || s.Status != "ok" || s.ProcessingSeconds >= 1 {
		t.Fatalf("returned write did not refresh progress: %+v", s)
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("batch did not finish")
	}
	saved := store.Global().LoadAllIPRecords()
	if len(saved) != 2 {
		t.Fatalf("saved %d records, want 2", len(saved))
	}
	for _, ip := range []string{"198.51.100.23", "203.0.113.24"} {
		if rec := saved[ip]; rec == nil || rec.EventCount != 1 {
			t.Fatalf("stored record missing or changed: %+v", rec)
		}
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.Status != "ok" || s.DroppedTotal != 0 {
		t.Fatalf("completed batch remained active: %+v", s)
	}
}

func TestAttackRecordQueueNormalizationAndPruning(t *testing.T) {
	db := eventQueueFlatDB(t)
	_, cleanup := setupBboltStore(t)
	t.Cleanup(cleanup)
	old := time.Now().Add(-100 * 24 * time.Hour)
	if err := store.Global().SaveIPRecord(store.IPRecord{IP: "198.51.100.23", FirstSeen: old, LastSeen: old, EventCount: 1, ThreatScore: 1, AttackCounts: map[string]int{string(AttackWebshell): 1}}); err != nil {
		t.Fatal(err)
	}
	db.load()
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 1 || s.DroppedTotal != 0 {
		t.Fatalf("normalized startup record missing: %+v", s)
	}
	db.PruneExpired()
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 1 || s.DroppedTotal != 0 {
		t.Fatalf("prune did not coalesce obsolete write: %+v", s)
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if saved := store.Global().LoadAllIPRecords(); len(saved) != 0 {
		t.Fatal("pruned startup record still persisted")
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
		t.Fatalf("prune persistence not retired: %+v", s)
	}
}
