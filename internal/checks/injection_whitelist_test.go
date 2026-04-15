package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// withNoStore ensures store.Global() returns nil so the file-fallback paths
// in addWhitelistEntry / RemoveWhitelist / loadPersistedWhitelist run.
func withNoStore(t *testing.T) {
	t.Helper()
	prev := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(prev) })
}

// --- AddWhitelist (permanent) -----------------------------------------

func TestAddWhitelistPersistsAndRemovesFromBadIPs(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)
	db.badIPs["198.51.100.1"] = "previously-bad"

	db.AddWhitelist("198.51.100.1")

	if !db.whitelist["198.51.100.1"] {
		t.Error("IP should be on whitelist after AddWhitelist")
	}
	if _, ok := db.badIPs["198.51.100.1"]; ok {
		t.Error("AddWhitelist should remove the IP from badIPs")
	}
	if entry := db.whitelistMeta["198.51.100.1"]; entry == nil || !entry.ExpiresAt.IsZero() {
		t.Errorf("permanent entry should have zero ExpiresAt, got %+v", entry)
	}
	// File must have been written.
	if _, err := os.Stat(filepath.Join(db.dbPath, "whitelist.txt")); err != nil {
		t.Errorf("whitelist.txt should exist after AddWhitelist: %v", err)
	}
}

// --- TempWhitelist (TTL) ----------------------------------------------

func TestTempWhitelistRecordsExpiresAt(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)
	ttl := 30 * time.Minute
	db.TempWhitelist("198.51.100.2", ttl)

	entry := db.whitelistMeta["198.51.100.2"]
	if entry == nil {
		t.Fatal("missing entry after TempWhitelist")
	}
	if entry.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be non-zero for temp whitelist")
	}
	if time.Until(entry.ExpiresAt) > ttl+time.Minute || time.Until(entry.ExpiresAt) < ttl-time.Minute {
		t.Errorf("ExpiresAt should be ~%v in the future, got %v", ttl, time.Until(entry.ExpiresAt))
	}
}

// --- RemoveWhitelist --------------------------------------------------

func TestRemoveWhitelistRewritesFile(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)
	db.AddWhitelist("198.51.100.3")
	db.AddWhitelist("198.51.100.4")

	db.RemoveWhitelist("198.51.100.3")

	if db.whitelist["198.51.100.3"] {
		t.Error("removed IP should be gone from whitelist")
	}
	if !db.whitelist["198.51.100.4"] {
		t.Error("other IPs should remain")
	}
	data, err := os.ReadFile(filepath.Join(db.dbPath, "whitelist.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "198.51.100.3") {
		t.Errorf("removed IP should not appear in file: %s", data)
	}
	if !strings.Contains(string(data), "198.51.100.4") {
		t.Errorf("remaining IP should still be in file: %s", data)
	}
}

// --- PruneExpiredWhitelist --------------------------------------------

func TestPruneExpiredWhitelistRemovesExpiredOnly(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)
	// Permanent entry — should survive.
	db.AddWhitelist("198.51.100.5")
	// Already-expired temp entry.
	db.whitelist["198.51.100.6"] = true
	db.whitelistMeta["198.51.100.6"] = &whitelistEntry{ExpiresAt: time.Now().Add(-1 * time.Hour)}
	// Future temp entry — should survive.
	db.whitelist["198.51.100.7"] = true
	db.whitelistMeta["198.51.100.7"] = &whitelistEntry{ExpiresAt: time.Now().Add(1 * time.Hour)}

	pruned := db.PruneExpiredWhitelist()
	if pruned != 1 {
		t.Errorf("expected 1 pruned, got %d", pruned)
	}
	if db.whitelist["198.51.100.6"] {
		t.Error("expired IP should be pruned")
	}
	if !db.whitelist["198.51.100.5"] || !db.whitelist["198.51.100.7"] {
		t.Error("permanent and future-expiry entries should survive")
	}
}

func TestPruneExpiredWhitelistNoExpired(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)
	db.AddWhitelist("198.51.100.8")

	if pruned := db.PruneExpiredWhitelist(); pruned != 0 {
		t.Errorf("nothing to prune should yield 0, got %d", pruned)
	}
}

// --- WhitelistedIPs ---------------------------------------------------

func TestWhitelistedIPsReportsPermanentAndTemp(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)
	db.AddWhitelist("203.0.113.1")
	db.TempWhitelist("203.0.113.2", 30*time.Minute)

	got := db.WhitelistedIPs()
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(got), got)
	}
	// Sorted alphabetically.
	if got[0].IP != "203.0.113.1" || got[1].IP != "203.0.113.2" {
		t.Errorf("expected alphabetical ordering, got %+v", got)
	}
	if !got[0].Permanent || got[0].ExpiresAt != nil {
		t.Errorf("first entry should be permanent: %+v", got[0])
	}
	if got[1].Permanent || got[1].ExpiresAt == nil {
		t.Errorf("second entry should be temp with ExpiresAt: %+v", got[1])
	}
}

func TestWhitelistedIPsEmpty(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)
	if got := db.WhitelistedIPs(); len(got) != 0 {
		t.Errorf("empty whitelist should return 0 entries, got %+v", got)
	}
}

// --- loadPersistedWhitelist (file fallback) ---------------------------

func TestLoadPersistedWhitelistParsesFlatFile(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)

	future := time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	expired := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	content := strings.Join([]string{
		"# header line",
		"203.0.113.10 permanent",
		"203.0.113.11 expires=" + future,
		"203.0.113.12 expires=" + expired,
		"not-an-ip foo",
		"",
	}, "\n") + "\n"

	if err := os.WriteFile(filepath.Join(db.dbPath, "whitelist.txt"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	db.loadPersistedWhitelist()

	if !db.whitelist["203.0.113.10"] {
		t.Error("permanent entry should be loaded")
	}
	if !db.whitelist["203.0.113.11"] {
		t.Error("future-expiry entry should be loaded")
	}
	if db.whitelist["203.0.113.12"] {
		t.Error("expired entry should NOT be loaded")
	}
	if db.whitelist["not-an-ip"] {
		t.Error("invalid IP line should be skipped")
	}
}

func TestLoadPersistedWhitelistMissingFileNoOp(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)
	// No whitelist.txt exists. Should not panic, should leave maps empty.
	db.loadPersistedWhitelist()
	if len(db.whitelist) != 0 {
		t.Errorf("missing file should leave whitelist empty, got %d entries", len(db.whitelist))
	}
}

// --- Store-backed branches --------------------------------------------

// withTestThreatStore swaps in a fresh bbolt-backed store so the
// store.Global() branches in addWhitelistEntry / RemoveWhitelist /
// loadPersistedWhitelist execute.
func withTestThreatStore(t *testing.T) {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})
}

func TestAddWhitelistEntryGoesThroughStoreWhenAvailable(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)
	db.AddWhitelist("203.0.113.50")

	// Verify in-memory state.
	if !db.whitelist["203.0.113.50"] {
		t.Fatal("entry should be in memory")
	}
	// File fallback must NOT have been written when store is available.
	if _, err := os.Stat(filepath.Join(db.dbPath, "whitelist.txt")); err == nil {
		t.Errorf("whitelist.txt should NOT exist when store is the persistence layer")
	}
	// And the store should have it.
	entries := store.Global().ListWhitelist()
	found := false
	for _, e := range entries {
		if e.IP == "203.0.113.50" && e.Permanent {
			found = true
		}
	}
	if !found {
		t.Errorf("store should contain the entry, got %+v", entries)
	}
}

func TestRemoveWhitelistGoesThroughStoreWhenAvailable(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)
	db.AddWhitelist("203.0.113.51")
	db.RemoveWhitelist("203.0.113.51")

	if db.whitelist["203.0.113.51"] {
		t.Error("in-memory entry should be removed")
	}
	for _, e := range store.Global().ListWhitelist() {
		if e.IP == "203.0.113.51" {
			t.Errorf("store should no longer contain removed entry, got %+v", e)
		}
	}
}

func TestLoadPersistedWhitelistFromStoreSkipsExpired(t *testing.T) {
	withTestThreatStore(t)
	sdb := store.Global()
	// Permanent entry — should be loaded.
	_ = sdb.AddWhitelistEntry("203.0.113.60", time.Time{}, true)
	// Already-expired temp entry — should be skipped.
	_ = sdb.AddWhitelistEntry("203.0.113.61", time.Now().Add(-1*time.Hour), false)
	// Future temp entry — should be loaded.
	_ = sdb.AddWhitelistEntry("203.0.113.62", time.Now().Add(1*time.Hour), false)

	db := newTestThreatDB(t)
	db.loadPersistedWhitelist()

	if !db.whitelist["203.0.113.60"] {
		t.Error("permanent store entry should be loaded")
	}
	if db.whitelist["203.0.113.61"] {
		t.Error("expired store entry should be skipped")
	}
	if !db.whitelist["203.0.113.62"] {
		t.Error("future-expiry store entry should be loaded")
	}
}
