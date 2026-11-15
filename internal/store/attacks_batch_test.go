package store

import (
	"errors"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// committedTx is the id of the last committed write transaction.
func committedTx(t *testing.T, db *DB) int {
	t.Helper()
	id := 0
	if err := db.bolt.View(func(tx *bolt.Tx) error { id = tx.ID(); return nil }); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestUpdateIPRecordsCommitsOnce(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err = db.SaveIPRecord(IPRecord{IP: "192.0.2.9", EventCount: 1}); err != nil {
		t.Fatal(err)
	}
	before := committedTx(t, db)
	err = db.UpdateIPRecords(func(w *IPRecordTx) error {
		for _, ip := range []string{"192.0.2.1", "198.51.100.2", "2001:db8::3"} {
			if saveErr := w.Save(IPRecord{IP: ip, EventCount: 2}); saveErr != nil {
				return saveErr
			}
		}
		return w.Delete("192.0.2.9")
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := committedTx(t, db) - before; got != 1 {
		t.Fatalf("three saves and a delete took %d transactions, want 1", got)
	}
	saved := db.LoadAllIPRecords()
	if len(saved) != 3 || saved["192.0.2.9"] != nil || saved["2001:db8::3"] == nil || saved["2001:db8::3"].EventCount != 2 {
		t.Fatalf("stored records: %v", saved)
	}
}

func TestUpdateIPRecordsKeepsOtherRecordsWhenOneIsRefused(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var refused error
	err = db.UpdateIPRecords(func(w *IPRecordTx) error {
		refused = w.Save(IPRecord{IP: ""})
		return w.Save(IPRecord{IP: "192.0.2.1", EventCount: 1})
	})
	if err != nil || refused == nil {
		t.Fatalf("err=%v refused=%v, want a refused record and a committed batch", err, refused)
	}
	if saved := db.LoadAllIPRecords(); len(saved) != 1 || saved["192.0.2.1"] == nil {
		t.Fatalf("stored records: %v", saved)
	}
}

func TestUpdateIPRecordsRollsBackOnError(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err = db.SaveIPRecord(IPRecord{IP: "192.0.2.9", EventCount: 1}); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop")
	err = db.UpdateIPRecords(func(w *IPRecordTx) error {
		if saveErr := w.Save(IPRecord{IP: "192.0.2.1", EventCount: 1}); saveErr != nil {
			return saveErr
		}
		if delErr := w.Delete("192.0.2.9"); delErr != nil {
			return delErr
		}
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("err=%v, want the callback's error", err)
	}
	if saved := db.LoadAllIPRecords(); len(saved) != 1 || saved["192.0.2.9"] == nil {
		t.Fatalf("a failed batch changed the store: %v", saved)
	}
}
