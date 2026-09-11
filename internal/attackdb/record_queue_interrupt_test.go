package attackdb

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

func TestAttackRecordQueueFailureVisibleDuringBatch(t *testing.T) {
	db := eventQueueFlatDB(t)
	_, cleanup := setupBboltStore(t)
	t.Cleanup(cleanup)
	for _, ip := range []string{"198.51.100.23", "203.0.113.24"} {
		db.RecordFinding(findingFromIP(ip))
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("batch did not join")
		}
	})
	failedIP := ""
	db.saveRecord = func(sdb *store.DB, rec store.IPRecord) error {
		if failedIP == "" {
			failedIP = rec.IP
			return errors.New("record write refused")
		}
		close(entered)
		<-release
		return sdb.SaveIPRecord(rec)
	}
	go func() { defer close(done); _ = db.Flush() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("second write did not start")
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 2 || s.DroppedTotal != 0 || s.Reason != "retry_failed" {
		t.Fatalf("returned failure hidden by later write: %+v", s)
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("batch did not finish")
	}
	saved := store.Global().LoadAllIPRecords()
	if len(saved) != 1 || saved[failedIP] != nil {
		t.Fatal("failed record was unexpectedly persisted")
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 1 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Reason != "retry_failed" {
		t.Fatalf("failed demand not retained exactly once: %+v", s)
	}
	db.saveRecord = nil
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	saved = store.Global().LoadAllIPRecords()
	if len(saved) != 2 || saved[failedIP] == nil || saved[failedIP].EventCount != 1 {
		t.Fatal("retained demand was not persisted on retry")
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
		t.Fatalf("successful retry not retired: %+v", s)
	}
}

func TestAttackRecordQueueInterruptedWriteRetiresActualDemand(t *testing.T) {
	for _, backend := range []string{"file", "bbolt"} {
		for _, exitMode := range []string{"panic", "goexit"} {
			t.Run(backend+"/"+exitMode, func(t *testing.T) {
				db := eventQueueFlatDB(t)
				if backend == "bbolt" {
					_, cleanup := setupBboltStore(t)
					t.Cleanup(cleanup)
				}
				for _, ip := range []string{"198.51.100.23", "203.0.113.24", "203.0.113.25"} {
					db.RecordFinding(findingFromIP(ip))
				}
				db.RemoveIP("192.0.2.26")
				interrupt := func() {
					if exitMode == "goexit" {
						runtime.Goexit()
					}
					panic("interrupted record commit")
				}
				calls := 0
				db.saveRecord = func(sdb *store.DB, rec store.IPRecord) error {
					calls++
					if err := sdb.SaveIPRecord(rec); err != nil {
						return err
					}
					interrupt()
					return nil
				}
				db.writeRecords = func(path string, data []byte) error {
					calls++
					if err := writeRecordFile(path, data); err != nil {
						return err
					}
					interrupt()
					return nil
				}
				returned, panicked := false, false
				done := make(chan struct{})
				go func() {
					defer close(done)
					defer func() { panicked = recover() != nil }()
					_ = db.Flush()
					returned = true
				}()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("interrupted flush did not release")
				}
				if calls != 1 || returned || panicked != (exitMode == "panic") {
					t.Fatalf("wrong boundary lifecycle: calls=%d returned=%v panicked=%v", calls, returned, panicked)
				}
				wantLoss, wantSaved := uint64(0), 3
				if backend == "bbolt" {
					wantLoss, wantSaved = 2, 1
				}
				restored := NewForTest(nil)
				restored.dbPath = db.dbPath
				restored.load()
				if got := restored.TotalIPs(); got != wantSaved {
					t.Fatalf("persisted %d, want %d", got, wantSaved)
				}
				if s := recordQueueStatus(t, db, time.Now()); s.Depth != 1 || s.InFlight != 0 || s.DroppedTotal != wantLoss || !s.DroppedLowerBound || s.Reason != "persistence_uncertain" {
					t.Fatalf("interrupted write lost actual retained/abandoned ownership: %+v", s)
				}
				db.saveRecord = nil
				db.writeRecords = nil
				db.saveRecords()
				if s := recordQueueStatus(t, db, time.Now().Add(2*time.Minute)); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != wantLoss || !s.DroppedLowerBound || s.Status != "ok" {
					t.Fatalf("retry concealed historical uncertainty or losses: %+v", s)
				}
			})
		}
	}
}

func TestAttackRecordQueueFailedShutdownRetainsRetry(t *testing.T) {
	db := eventQueueFlatDB(t)
	db.RecordFinding(findingFromIP("198.51.100.23"))
	db.writeRecords = func(string, []byte) error { return errors.New("record shutdown write refused") }
	db.Stop()
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 1 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Reason != "retry_failed" {
		t.Fatalf("failed shutdown falsely completed demand: %+v", s)
	}
	db.writeRecords = nil
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	restored := NewForTest(nil)
	restored.dbPath = db.dbPath
	restored.load()
	if rec := restored.LookupIP("198.51.100.23"); rec == nil || rec.EventCount != 1 {
		t.Fatal("explicit retry after shutdown did not persist retained demand")
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
		t.Fatalf("explicit retry did not finish: %+v", s)
	}
}

func TestAttackRecordQueueInterruptedDeleteRetainsUncertainty(t *testing.T) {
	db := eventQueueFlatDB(t)
	_, cleanup := setupBboltStore(t)
	t.Cleanup(cleanup)
	db.RecordFinding(findingFromIP("198.51.100.23"))
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	db.RemoveIP("198.51.100.23")
	db.deleteRecord = func(sdb *store.DB, ip string) error {
		if err := sdb.DeleteIPRecord(ip); err != nil {
			return err
		}
		panic("delete committed without returning")
	}
	panicked := false
	func() { defer func() { panicked = recover() != nil }(); _ = db.Flush() }()
	if !panicked {
		t.Fatal("delete interruption was swallowed")
	}
	if saved := store.Global().LoadAllIPRecords(); len(saved) != 0 {
		t.Fatal("delete did not reach actual commit")
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 1 || s.InFlight != 0 || s.DroppedTotal != 0 || !s.DroppedLowerBound || s.Reason != "persistence_uncertain" {
		t.Fatalf("retained deletion concealed interrupted commit: %+v", s)
	}
	db.deleteRecord = nil
	db.saveRecords()
	if s := recordQueueStatus(t, db, time.Now().Add(2*time.Minute)); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || !s.DroppedLowerBound || s.Status != "ok" {
		t.Fatalf("completed delete retry lost uncertainty history: %+v", s)
	}
}

func TestAttackRecordQueueInterruptionVisibleBeforeStateCleanup(t *testing.T) {
	for _, exitMode := range []string{"panic", "goexit"} {
		t.Run(exitMode, func(t *testing.T) {
			db := eventQueueFlatDB(t)
			_, cleanup := setupBboltStore(t)
			t.Cleanup(cleanup)
			db.RecordFinding(findingFromIP("198.51.100.23"))
			entered, release, exited, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			locked := false
			t.Cleanup(func() {
				if locked {
					db.mu.Unlock()
				}
				unblock()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("interrupted cleanup did not join")
				}
			})
			db.saveRecord = func(sdb *store.DB, rec store.IPRecord) error {
				close(entered)
				<-release
				defer close(exited)
				if err := sdb.SaveIPRecord(rec); err != nil {
					return err
				}
				if exitMode == "goexit" {
					runtime.Goexit()
				}
				panic("interrupted before state cleanup")
			}
			returned, panicked := false, false
			go func() {
				defer close(done)
				defer func() { panicked = recover() != nil }()
				_ = db.Flush()
				returned = true
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("writer did not start")
			}
			db.mu.Lock()
			locked = true
			unblock()
			select {
			case <-exited:
			case <-time.After(5 * time.Second):
				t.Fatal("writer did not exit")
			}
			deadline := time.Now().Add(time.Second)
			for {
				s := recordQueueStatus(t, db, time.Now())
				if s.Reason == "persistence_uncertain" {
					if !s.DroppedLowerBound || s.Depth != 0 || s.InFlight != 1 || s.DroppedTotal != 0 {
						t.Fatalf("blocked state cleanup changed ownership: %+v", s)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("state cleanup hid unreturned commit: %+v", s)
				}
				time.Sleep(time.Millisecond)
			}
			db.mu.Unlock()
			locked = false
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("cleanup did not finish")
			}
			if returned || panicked != (exitMode == "panic") {
				t.Fatalf("exit behavior changed: returned=%v panicked=%v", returned, panicked)
			}
			saved := store.Global().LoadAllIPRecords()
			if len(saved) != 1 || saved["198.51.100.23"] == nil || saved["198.51.100.23"].EventCount != 1 {
				t.Fatal("interrupted write did not reach real persistence")
			}
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || !s.DroppedLowerBound {
				t.Fatalf("cleanup erased unknown outcome: %+v", s)
			}
		})
	}
}
