package attackdb

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

func findingFromIP(ip string) alert.Finding {
	return alert.Finding{Check: "webshell", Message: "attack from " + ip, Timestamp: time.Now()}
}

// RecordFinding must mark the affected IP dirty so the next flush persists it.
func TestRecordFindingMarksIPDirty(t *testing.T) {
	db := newTestDB(t)
	db.RecordFinding(findingFromIP("203.0.113.7"))
	if _, ok := db.dirtyIPs["203.0.113.7"]; !ok {
		t.Fatalf("RecordFinding should mark the IP dirty; dirtyIPs=%v", db.dirtyIPs)
	}
}

// MarkBlocked mutates a record, so it too must mark the IP dirty.
func TestMarkBlockedMarksIPDirty(t *testing.T) {
	db := newTestDB(t)
	db.RecordFinding(findingFromIP("203.0.113.7"))
	delete(db.dirtyIPs, "203.0.113.7") // clear the mark left by RecordFinding
	db.MarkBlocked("203.0.113.7")
	if _, ok := db.dirtyIPs["203.0.113.7"]; !ok {
		t.Fatal("MarkBlocked should mark the IP dirty")
	}
}

// saveRecords must drain the dirty set so the following flush only writes
// records changed since this one.
func TestSaveRecordsClearsDirtyIPs(t *testing.T) {
	dir, cleanup := setupBboltStore(t)
	defer cleanup()
	db := newTestDB(t)
	db.dbPath = dir
	db.RecordFinding(findingFromIP("203.0.113.7"))
	db.saveRecords()
	if len(db.dirtyIPs) != 0 {
		t.Fatalf("saveRecords should drain dirtyIPs, got %v", db.dirtyIPs)
	}
}

// Core perf contract: a record not marked dirty is NOT re-serialized to the
// store. Fails on the old full-rewrite path; passes once saveRecords is
// incremental.
func TestSaveRecordsSkipsCleanRecords(t *testing.T) {
	dir, cleanup := setupBboltStore(t)
	defer cleanup()
	sdb := store.Global()
	if err := sdb.SaveIPRecord(store.IPRecord{
		IP: "203.0.113.5", EventCount: 5, ThreatScore: 10,
		FirstSeen: time.Now(), LastSeen: time.Now(),
		AttackCounts: map[string]int{}, Accounts: map[string]int{},
	}); err != nil {
		t.Fatal(err)
	}
	db := newTestDB(t)
	db.dbPath = dir
	db.load() // records loaded, dirtyIPs empty

	// Mutate in memory WITHOUT marking dirty: the old full-rewrite path would
	// needlessly re-serialize this; the incremental path must skip it.
	db.records["203.0.113.5"].EventCount = 99
	db.saveRecords()

	got := sdb.LoadAllIPRecords()["203.0.113.5"]
	if got == nil {
		t.Fatal("record vanished from store")
	}
	if got.EventCount != 5 {
		t.Fatalf("clean record was rewritten (EventCount=%d, want 5); incremental save must skip non-dirty records", got.EventCount)
	}
}

// Do-not-break: an incremental flush that writes one dirty record must not drop
// the other records already persisted in the store.
func TestSaveRecordsKeepsUntouchedRecords(t *testing.T) {
	dir, cleanup := setupBboltStore(t)
	defer cleanup()
	sdb := store.Global()
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if err := sdb.SaveIPRecord(store.IPRecord{
			IP: ip, EventCount: 1, ThreatScore: 2, FirstSeen: time.Now(), LastSeen: time.Now(),
			AttackCounts: map[string]int{}, Accounts: map[string]int{},
		}); err != nil {
			t.Fatal(err)
		}
	}
	db := newTestDB(t)
	db.dbPath = dir
	db.load()

	db.RecordFinding(findingFromIP("203.0.113.2")) // only .2 changes
	db.saveRecords()

	got := sdb.LoadAllIPRecords()
	if got["203.0.113.1"] == nil {
		t.Fatal("untouched record .1 must remain in the store after an incremental flush")
	}
	if got["203.0.113.2"] == nil {
		t.Fatal("dirty record .2 must be persisted")
	}
}

func TestRecordFindingAfterRemoveCancelsPendingDelete(t *testing.T) {
	dir, cleanup := setupBboltStore(t)
	defer cleanup()
	sdb := store.Global()
	now := time.Now()
	if err := sdb.SaveIPRecord(store.IPRecord{
		IP: "203.0.113.9", EventCount: 7,
		FirstSeen: now, LastSeen: now,
		AttackCounts: map[string]int{"brute_force": 7}, Accounts: map[string]int{},
	}); err != nil {
		t.Fatal(err)
	}
	db := newTestDB(t)
	db.dbPath = dir
	db.load()

	db.RemoveIP("203.0.113.9")
	db.RecordFinding(findingFromIP("203.0.113.9"))
	db.saveRecords()

	got := sdb.LoadAllIPRecords()["203.0.113.9"]
	if got == nil {
		t.Fatal("record re-added before flush must not be deleted from the store")
	}
	if got.EventCount != 1 {
		t.Fatalf("re-added record EventCount=%d, want 1", got.EventCount)
	}
	if _, pending := db.deletedIPs["203.0.113.9"]; pending {
		t.Fatal("record mutation should cancel the stale pending delete")
	}
}

func TestSaveRecordsRetriesFailedBboltDeletes(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(sdb)
	defer store.SetGlobal(nil)
	now := time.Now()
	if err := sdb.SaveIPRecord(store.IPRecord{
		IP: "203.0.113.10", EventCount: 1,
		FirstSeen: now, LastSeen: now,
		AttackCounts: map[string]int{}, Accounts: map[string]int{},
	}); err != nil {
		t.Fatal(err)
	}
	db := newTestDB(t)
	db.deletedIPs["203.0.113.10"] = struct{}{}

	if err := sdb.Close(); err != nil {
		t.Fatal(err)
	}
	db.saveRecords()

	if _, pending := db.deletedIPs["203.0.113.10"]; !pending {
		t.Fatal("failed delete should stay pending")
	}
	if !db.dirty {
		t.Fatal("failed delete should leave the database dirty for retry")
	}
}

func TestSaveRecordsRetriesFailedFlatFileDeletes(t *testing.T) {
	previous := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previous) })

	db := &DB{
		records:    make(map[string]*IPRecord),
		deletedIPs: map[string]struct{}{"203.0.113.10": {}},
		dbPath:     filepath.Join(t.TempDir(), "missing", "attack_db"),
		stopCh:     make(chan struct{}),
	}

	db.saveRecords()

	if _, pending := db.deletedIPs["203.0.113.10"]; !pending {
		t.Fatal("failed flat-file delete should stay pending")
	}
	if !db.dirty {
		t.Fatal("failed flat-file delete should leave the database dirty for retry")
	}
}

func TestLoadMarksNormalizedBboltRecordDirty(t *testing.T) {
	dir, cleanup := setupBboltStore(t)
	defer cleanup()
	sdb := store.Global()
	now := time.Now()
	if err := sdb.SaveIPRecord(store.IPRecord{
		IP:          "203.0.113.11",
		EventCount:  1,
		ThreatScore: 1,
		FirstSeen:   now,
		LastSeen:    now,
		AttackCounts: map[string]int{
			string(AttackWebshell): 1,
		},
		Accounts: map[string]int{},
	}); err != nil {
		t.Fatal(err)
	}

	db := newTestDB(t)
	db.dbPath = dir
	db.load()

	rec := db.records["203.0.113.11"]
	if rec == nil {
		t.Fatal("record was not loaded")
	}
	if rec.ThreatScore == 1 {
		t.Fatal("load should normalize the stale stored threat score")
	}
	if _, ok := db.dirtyIPs["203.0.113.11"]; !ok {
		t.Fatal("normalized record should be marked dirty for the next flush")
	}

	db.saveRecords()
	got := sdb.LoadAllIPRecords()["203.0.113.11"]
	if got == nil {
		t.Fatal("record vanished from store")
	}
	if got.ThreatScore != rec.ThreatScore {
		t.Fatalf("stored ThreatScore=%d, want normalized score %d", got.ThreatScore, rec.ThreatScore)
	}
}

func TestLoadDoesNotMarkCleanBboltRecordDirty(t *testing.T) {
	dir, cleanup := setupBboltStore(t)
	defer cleanup()
	sdb := store.Global()
	now := time.Now()
	if err := sdb.SaveIPRecord(store.IPRecord{
		IP:           "203.0.113.12",
		EventCount:   0,
		ThreatScore:  0,
		FirstSeen:    now,
		LastSeen:     now,
		AttackCounts: map[string]int{},
		Accounts:     map[string]int{},
	}); err != nil {
		t.Fatal(err)
	}

	db := newTestDB(t)
	db.dbPath = dir
	db.load()

	if _, ok := db.dirtyIPs["203.0.113.12"]; ok {
		t.Fatal("empty-map normalization alone should not force a rewrite")
	}
}
