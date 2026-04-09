package attackdb

import (
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
	defer sdb.Close()
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
	db.saveRecords()

	db.RemoveIP("203.0.113.5")
	db.saveRecords()

	if recs := sdb.LoadAllIPRecords(); recs["203.0.113.5"] != nil {
		t.Fatal("deleted IP record should be removed from bbolt store")
	}
}
