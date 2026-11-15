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

func TestFlushOverlappingSaveDoesNotHideDeleteFailure(t *testing.T) {
	db := eventQueueFlatDB(t)
	_, cleanup := setupBboltStore(t)
	t.Cleanup(cleanup)
	const ip = "192.0.2.9"
	db.RecordFinding(findingFromIP(ip))
	// Keep both operations in the snapshot to exercise their shared health key.
	db.deletedIPs[ip] = struct{}{}
	db.deleteRecord = func(*store.IPRecordTx, string) error { return errors.New("delete refused") }
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if rec, ok := store.Global().LoadIPRecord(ip); !ok || rec.EventCount != 1 {
		t.Fatalf("successful save did not commit: %+v, %v", rec, ok)
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 1 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Reason != "retry_failed" {
		t.Fatalf("successful save hid refused delete: %+v", s)
	}
	db.deleteRecord = nil
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Global().LoadIPRecord(ip); ok {
		t.Fatal("delete did not retry")
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
		t.Fatalf("delete retry not retired: %+v", s)
	}
}

func TestFlushRefusedBatchCommitRefreshesProgress(t *testing.T) {
	db := eventQueueFlatDB(t)
	_, cleanup := setupBboltStore(t)
	t.Cleanup(cleanup)
	db.RecordFinding(findingFromIP("192.0.2.9"))
	db.saveRecord = func(*store.IPRecordTx, store.IPRecord) error { return errors.New("save refused") }
	var batch *recordBatch
	db.updateRecords = func(sdb *store.DB, fn func(*store.IPRecordTx) error) error {
		return sdb.UpdateIPRecords(func(w *store.IPRecordTx) error {
			if err := fn(w); err != nil {
				return err
			}
			q := db.recordHealth()
			q.mu.Lock()
			batch = q.active
			batch.progress = time.Now().Add(-2 * time.Minute)
			q.mu.Unlock()
			return nil
		})
	}
	before := time.Now()
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if batch == nil || batch.progress.Before(before) {
		t.Fatal("returned commit did not refresh progress when every record was refused")
	}
}

func TestFlushOverlappingDeletePreservesSaveRefusal(t *testing.T) {
	db := eventQueueFlatDB(t)
	_, cleanup := setupBboltStore(t)
	t.Cleanup(cleanup)
	const ip = "192.0.2.9"
	db.RecordFinding(findingFromIP(ip))
	db.deletedIPs[ip] = struct{}{}
	db.saveRecord = func(*store.IPRecordTx, store.IPRecord) error { return errors.New("save refused") }
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Global().LoadIPRecord(ip); ok {
		t.Fatal("failed save was persisted")
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 1 || s.InFlight != 0 || s.DroppedTotal != 0 || s.DroppedLowerBound || s.Reason != "retry_failed" {
		t.Fatalf("returned save refusal was lost: %+v", s)
	}
	db.saveRecord = nil
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if rec, ok := store.Global().LoadIPRecord(ip); !ok || rec.EventCount != 1 {
		t.Fatalf("save did not retry: %+v, %v", rec, ok)
	}
	if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.DroppedLowerBound || s.Status != "ok" {
		t.Fatalf("save retry not retired: %+v", s)
	}
}

func TestFlushTransactionFailureRetriesWholeBatch(t *testing.T) {
	for _, boundary := range []string{"begin", "commit"} {
		t.Run(boundary, func(t *testing.T) {
			db := eventQueueFlatDB(t)
			_, cleanup := setupBboltStore(t)
			t.Cleanup(cleanup)
			const deletedIP = "192.0.2.9"
			if err := store.Global().SaveIPRecord(store.IPRecord{IP: deletedIP}); err != nil {
				t.Fatal(err)
			}
			for _, ip := range []string{"198.51.100.23", "203.0.113.24"} {
				db.RecordFinding(findingFromIP(ip))
			}
			db.RemoveIP(deletedIP)
			calls := 0
			db.saveRecord = func(w *store.IPRecordTx, rec store.IPRecord) error {
				calls++
				if rec.IP == "198.51.100.23" {
					return errors.New("record refused")
				}
				return w.Save(rec)
			}
			failure := errors.New("transaction failed")
			db.updateRecords = func(sdb *store.DB, fn func(*store.IPRecordTx) error) error {
				if boundary == "begin" {
					return failure
				}
				return sdb.UpdateIPRecords(func(w *store.IPRecordTx) error {
					if err := fn(w); err != nil {
						return err
					}
					q := db.recordHealth()
					q.mu.Lock()
					defer q.mu.Unlock()
					for ip, demand := range q.active.items {
						if demand.phase == recordSucceeded {
							t.Errorf("%s reported success before commit returned", ip)
						}
					}
					return failure
				})
			}
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			wantCalls := 0
			if boundary == "commit" {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("save calls = %d, want %d", calls, wantCalls)
			}
			if saved := store.Global().LoadAllIPRecords(); len(saved) != 1 || saved[deletedIP] == nil {
				t.Fatalf("failed transaction changed store: %v", saved)
			}
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 3 || s.InFlight != 0 || s.DroppedTotal != 0 || s.DroppedLowerBound || s.Reason != "retry_failed" {
				t.Fatalf("failed transaction did not retain all demand: %+v", s)
			}
			db.saveRecord, db.updateRecords = nil, nil
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}
			saved := store.Global().LoadAllIPRecords()
			if len(saved) != 2 || saved["198.51.100.23"] == nil || saved["203.0.113.24"] == nil {
				t.Fatalf("retry did not persist exact batch: %v", saved)
			}
			if s := recordQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.DroppedLowerBound || s.Status != "ok" {
				t.Fatalf("successful retry did not retire demand: %+v", s)
			}
		})
	}
}

func TestSaveRecordsEmptyDoesNotOpenTransaction(t *testing.T) {
	db := eventQueueFlatDB(t)
	_, cleanup := setupBboltStore(t)
	t.Cleanup(cleanup)
	updates := 0
	db.updateRecords = func(sdb *store.DB, fn func(*store.IPRecordTx) error) error {
		updates++
		return sdb.UpdateIPRecords(fn)
	}
	// Flush's dirty gate must not be the only guard against an empty write.
	db.saveRecords()
	if updates != 0 {
		t.Fatalf("empty persistence snapshot opened %d transactions", updates)
	}
}
