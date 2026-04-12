package attackdb

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

func setupBboltStore(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(sdb)
	return dir, func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	}
}

func TestLoadViaBbolt(t *testing.T) {
	dir, cleanup := setupBboltStore(t)
	defer cleanup()

	// Seed a record via the store directly
	sdb := store.Global()
	_ = sdb.SaveIPRecord(store.IPRecord{
		IP: "203.0.113.5", EventCount: 10, ThreatScore: 50,
		FirstSeen: time.Now(), LastSeen: time.Now(),
		AttackCounts: map[string]int{"brute_force": 5},
		Accounts:     map[string]int{"alice": 3},
	})

	db := newTestDB(t)
	db.dbPath = dir
	db.load()

	if db.TotalIPs() != 1 {
		t.Errorf("loaded %d records, want 1", db.TotalIPs())
	}
	rec := db.records["203.0.113.5"]
	if rec == nil {
		t.Fatal("record not found")
	}
	if rec.EventCount != 10 {
		t.Errorf("EventCount = %d", rec.EventCount)
	}
}

func TestSaveRecordsViaBbolt(t *testing.T) {
	dir, cleanup := setupBboltStore(t)
	defer cleanup()

	db := newTestDB(t)
	db.dbPath = dir
	db.records["203.0.113.5"] = &IPRecord{
		IP: "203.0.113.5", EventCount: 5, ThreatScore: 30,
		FirstSeen: time.Now(), LastSeen: time.Now(),
		AttackCounts: map[AttackType]int{AttackBruteForce: 3},
		Accounts:     map[string]int{"bob": 1},
	}
	db.saveRecords()

	// Verify via store
	loaded := store.Global().LoadAllIPRecords()
	if len(loaded) != 1 {
		t.Errorf("stored %d records, want 1", len(loaded))
	}
}

func TestSaveRecordsDeletesViaBbolt(t *testing.T) {
	dir, cleanup := setupBboltStore(t)
	defer cleanup()

	sdb := store.Global()
	_ = sdb.SaveIPRecord(store.IPRecord{
		IP: "203.0.113.5", EventCount: 1,
		FirstSeen: time.Now(), LastSeen: time.Now(),
		AttackCounts: map[string]int{}, Accounts: map[string]int{},
	})

	db := newTestDB(t)
	db.dbPath = dir
	db.load()
	db.RemoveIP("203.0.113.5")
	db.saveRecords()

	loaded := sdb.LoadAllIPRecords()
	if len(loaded) != 0 {
		t.Errorf("deleted IP should not be in store, got %d", len(loaded))
	}
}

func TestAppendEventsViaBbolt(t *testing.T) {
	_, cleanup := setupBboltStore(t)
	defer cleanup()

	db := newTestDB(t)
	events := []Event{
		{IP: "203.0.113.5", AttackType: AttackBruteForce, CheckName: "ssh", Message: "test", Timestamp: time.Now()},
	}
	db.appendEvents(events)

	// Verify via store — events should be stored
	sdb := store.Global()
	stored := sdb.ReadAllAttackEvents()
	if len(stored) != 1 {
		t.Errorf("stored %d events, want 1", len(stored))
	}
}

func TestQueryEventsViaBbolt(t *testing.T) {
	dir, cleanup := setupBboltStore(t)
	defer cleanup()

	db := newTestDB(t)
	db.dbPath = dir
	db.appendEvents([]Event{
		{IP: "203.0.113.5", AttackType: AttackBruteForce, CheckName: "ssh", Message: "test", Timestamp: time.Now()},
		{IP: "198.51.100.1", AttackType: AttackWebshell, CheckName: "wshell", Message: "test2", Timestamp: time.Now()},
	})

	events := db.QueryEvents("203.0.113.5", 10)
	if len(events) != 1 {
		t.Errorf("got %d events for 203.0.113.5, want 1", len(events))
	}
}
