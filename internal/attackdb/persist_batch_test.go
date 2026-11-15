package attackdb

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

func TestFlushWritesStoreRecordsInOneTransaction(t *testing.T) {
	db := eventQueueFlatDB(t)
	_, cleanup := setupBboltStore(t)
	t.Cleanup(cleanup)
	db.RecordFinding(findingFromIP("192.0.2.9"))
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"198.51.100.23", "203.0.113.24", "203.0.113.25"} {
		db.RecordFinding(findingFromIP(ip))
	}
	db.RemoveIP("192.0.2.9")
	updates := 0
	db.updateRecords = func(sdb *store.DB, fn func(*store.IPRecordTx) error) error {
		updates++
		return sdb.UpdateIPRecords(fn)
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if updates != 1 {
		t.Fatalf("three saves and a delete took %d store transactions, want 1", updates)
	}
	saved := store.Global().LoadAllIPRecords()
	if len(saved) != 3 || saved["192.0.2.9"] != nil || saved["203.0.113.25"] == nil {
		t.Fatalf("stored records: %v", saved)
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
		t.Fatalf("flushed batch left demand: %+v", s)
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if updates != 1 {
		t.Fatalf("a flush with nothing to write opened %d more transactions", updates-1)
	}
}

func TestFlushCommitFailureKeepsEveryRecordQueued(t *testing.T) {
	db := eventQueueFlatDB(t)
	_, cleanup := setupBboltStore(t)
	t.Cleanup(cleanup)
	db.RecordFinding(findingFromIP("192.0.2.9"))
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"198.51.100.23", "203.0.113.24"} {
		db.RecordFinding(findingFromIP(ip))
	}
	db.RemoveIP("192.0.2.9")
	db.updateRecords = func(sdb *store.DB, fn func(*store.IPRecordTx) error) error {
		return sdb.UpdateIPRecords(func(w *store.IPRecordTx) error {
			if err := fn(w); err != nil {
				return err
			}
			return errors.New("commit refused")
		})
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if saved := store.Global().LoadAllIPRecords(); len(saved) != 1 || saved["192.0.2.9"] == nil {
		t.Fatalf("a refused commit changed the store: %v", saved)
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 3 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Reason != "retry_failed" {
		t.Fatalf("refused commit did not keep every record for retry: %+v", s)
	}
	db.updateRecords = nil
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	saved := store.Global().LoadAllIPRecords()
	if len(saved) != 2 || saved["192.0.2.9"] != nil || saved["198.51.100.23"] == nil || saved["203.0.113.24"] == nil {
		t.Fatalf("retry did not persist the batch: %v", saved)
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
		t.Fatalf("successful retry not retired: %+v", s)
	}
}
