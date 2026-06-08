package attackdb

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

func TestSaveRecordsDeletesRemovedIPsFromStore(t *testing.T) {
	stateDir := t.TempDir()
	sdb, err := store.Open(stateDir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = sdb.Close() }()
	store.SetGlobal(sdb)
	defer store.SetGlobal(nil)

	db := &DB{
		records:    make(map[string]*IPRecord),
		deletedIPs: make(map[string]struct{}),
		dbPath:     filepath.Join(stateDir, "attack_db"),
		stopCh:     make(chan struct{}),
	}

	db.records["203.0.113.5"] = &IPRecord{
		IP:           "203.0.113.5",
		FirstSeen:    time.Now(),
		LastSeen:     time.Now(),
		AttackCounts: make(map[AttackType]int),
		Accounts:     make(map[string]int),
	}
	db.dirtyIPs = map[string]struct{}{"203.0.113.5": {}}
	db.saveRecords() // record now actually persisted to the store

	db.RemoveIP("203.0.113.5")
	db.saveRecords()

	if recs := sdb.LoadAllIPRecords(); recs["203.0.113.5"] != nil {
		t.Fatal("deleted IP record should be removed from bbolt store")
	}
}

// On a host with no bbolt store, saveRecords rewrites the whole flat file so
// removals are reflected by absence -- but it must still drain deletedIPs, or
// that set grows for the process lifetime.
func TestSaveRecordsDrainsDeletedIPsInFlatFileMode(t *testing.T) {
	store.SetGlobal(nil) // force the flat-file branch

	stateDir := t.TempDir()
	dbPath := filepath.Join(stateDir, "attack_db")
	if err := os.MkdirAll(dbPath, 0700); err != nil {
		t.Fatal(err)
	}
	db := &DB{
		records:    make(map[string]*IPRecord),
		deletedIPs: make(map[string]struct{}),
		dbPath:     dbPath,
		stopCh:     make(chan struct{}),
	}

	db.records["203.0.113.7"] = &IPRecord{
		IP:           "203.0.113.7",
		FirstSeen:    time.Now(),
		LastSeen:     time.Now(),
		AttackCounts: make(map[AttackType]int),
		Accounts:     make(map[string]int),
	}
	db.saveRecords()

	db.RemoveIP("203.0.113.7")
	if _, ok := db.deletedIPs["203.0.113.7"]; !ok {
		t.Fatal("precondition: RemoveIP should record the deletion")
	}
	db.saveRecords()

	db.mu.RLock()
	n := len(db.deletedIPs)
	db.mu.RUnlock()
	if n != 0 {
		t.Fatalf("deletedIPs not drained in flat-file mode: %d remaining", n)
	}
}
