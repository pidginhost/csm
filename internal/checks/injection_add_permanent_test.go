package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

// AddPermanent adds an IP to the permanent blocklist. Behaviour:
//   - duplicate IP → updates in-memory entry, no persistence
//   - first add with store.Global → goes through bbolt
//   - first add without store → appends to permanent.txt

func TestAddPermanentDedupesSamIP(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)
	db.AddPermanent("203.0.113.1", "first reason")
	db.AddPermanent("203.0.113.1", "second reason") // duplicate

	if db.badIPs["203.0.113.1"] != "second reason" {
		t.Errorf("in-memory should be updated to latest reason, got %q", db.badIPs["203.0.113.1"])
	}
	// permanent.txt should have only one entry despite two calls.
	data, err := os.ReadFile(filepath.Join(db.dbPath, "permanent.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(data), "203.0.113.1"); count != 1 {
		t.Errorf("permanent.txt should have 1 entry for deduped IP, got %d", count)
	}
}

func TestAddPermanentAppendsToFileWhenNoStore(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)
	db.AddPermanent("203.0.113.10", "brute-force")
	db.AddPermanent("203.0.113.11", "port scan")

	data, err := os.ReadFile(filepath.Join(db.dbPath, "permanent.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expect := range []string{"203.0.113.10", "brute-force", "203.0.113.11", "port scan"} {
		if !strings.Contains(string(data), expect) {
			t.Errorf("permanent.txt should contain %q: %s", expect, data)
		}
	}
}

func TestAddPermanentRoutesThroughStoreWhenAvailable(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)
	db.AddPermanent("203.0.113.20", "auto-block")

	// File fallback MUST NOT have been used when store is available.
	if _, err := os.Stat(filepath.Join(db.dbPath, "permanent.txt")); err == nil {
		t.Error("permanent.txt should not be written when store is active")
	}
	// And the store must carry the entry.
	entry, found := store.Global().GetPermanentBlock("203.0.113.20")
	if !found {
		t.Errorf("store should contain the entry, got %+v", entry)
	}
	if entry.Reason != "auto-block" {
		t.Errorf("reason mismatch: %q", entry.Reason)
	}
}

// loadPermanentBlocklist — parses permanent.txt format "IP reason...".

func TestLoadPermanentBlocklistFromFile(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)

	content := strings.Join([]string{
		"# header comment",
		"",
		"203.0.113.100 brute-force from ssh",
		"203.0.113.101 port scan",
		"not-an-ip garbage",
		"10.0.0.1 private but allowed in permanent",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(db.dbPath, "permanent.txt"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	db.loadPermanentBlocklist()

	// loadPermanentBlocklist stores a fixed "permanent-blocklist" tag;
	// the per-entry reason column is not preserved here.
	if reason := db.badIPs["203.0.113.100"]; reason != "permanent-blocklist" {
		t.Errorf("expected 'permanent-blocklist' tag, got %q", reason)
	}
	if _, ok := db.badIPs["203.0.113.101"]; !ok {
		t.Errorf(".101 should be in badIPs, got %v", db.badIPs)
	}
	if _, ok := db.badIPs["not-an-ip"]; ok {
		t.Errorf("invalid IP should be skipped, got %v", db.badIPs)
	}
}

func TestLoadPermanentBlocklistMissingFileNoOp(t *testing.T) {
	withNoStore(t)
	db := newTestThreatDB(t)
	db.loadPermanentBlocklist() // no permanent.txt
	if len(db.badIPs) != 0 {
		t.Errorf("missing file should leave badIPs empty, got %v", db.badIPs)
	}
}
