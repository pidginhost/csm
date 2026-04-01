package store

import (
	"testing"
	"time"
)

func TestAddRemovePermanent(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	// Add 2 IPs.
	if err := db.AddPermanentBlock("10.0.0.1", "brute-force"); err != nil {
		t.Fatalf("AddPermanentBlock(10.0.0.1): %v", err)
	}
	if err := db.AddPermanentBlock("10.0.0.2", "php-shell"); err != nil {
		t.Fatalf("AddPermanentBlock(10.0.0.2): %v", err)
	}

	// Verify count = 2.
	count := db.getCounter("threats:count")
	if count != 2 {
		t.Fatalf("threats:count = %d, want 2", count)
	}

	// Lookup one — found with correct reason.
	entry, found := db.GetPermanentBlock("10.0.0.1")
	if !found {
		t.Fatal("GetPermanentBlock(10.0.0.1): not found")
	}
	if entry.Reason != "brute-force" {
		t.Fatalf("Reason = %q, want %q", entry.Reason, "brute-force")
	}

	// Remove it.
	if err := db.RemovePermanentBlock("10.0.0.1"); err != nil {
		t.Fatalf("RemovePermanentBlock(10.0.0.1): %v", err)
	}

	// Count = 1.
	count = db.getCounter("threats:count")
	if count != 1 {
		t.Fatalf("threats:count = %d, want 1", count)
	}

	// Lookup removed IP — not found.
	_, found = db.GetPermanentBlock("10.0.0.1")
	if found {
		t.Fatal("GetPermanentBlock(10.0.0.1) should not be found after removal")
	}

	// Other IP still present.
	entry, found = db.GetPermanentBlock("10.0.0.2")
	if !found {
		t.Fatal("GetPermanentBlock(10.0.0.2): not found")
	}
	if entry.Reason != "php-shell" {
		t.Fatalf("Reason = %q, want %q", entry.Reason, "php-shell")
	}
}

func TestWhitelistWithExpiry(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	now := time.Now()

	// Add permanent entry.
	if err := db.AddWhitelistEntry("192.168.1.1", time.Time{}, true); err != nil {
		t.Fatalf("AddWhitelistEntry(permanent): %v", err)
	}

	// Add temp entry expiring 1 hour in the future.
	if err := db.AddWhitelistEntry("192.168.1.2", now.Add(1*time.Hour), false); err != nil {
		t.Fatalf("AddWhitelistEntry(future): %v", err)
	}

	// Add already-expired entry.
	if err := db.AddWhitelistEntry("192.168.1.3", now.Add(-1*time.Hour), false); err != nil {
		t.Fatalf("AddWhitelistEntry(expired): %v", err)
	}

	// All 3 should be in the list.
	all := db.ListWhitelist()
	if len(all) != 3 {
		t.Fatalf("ListWhitelist len = %d, want 3", len(all))
	}

	// IsWhitelisted checks.
	if !db.IsWhitelisted("192.168.1.1") {
		t.Fatal("permanent entry should be whitelisted")
	}
	if !db.IsWhitelisted("192.168.1.2") {
		t.Fatal("future entry should be whitelisted")
	}
	if db.IsWhitelisted("192.168.1.3") {
		t.Fatal("expired entry should not be whitelisted")
	}

	// Prune — should remove 1 expired entry.
	removed := db.PruneExpiredWhitelist()
	if removed != 1 {
		t.Fatalf("PruneExpiredWhitelist = %d, want 1", removed)
	}

	// Verify expired is gone, others remain.
	remaining := db.ListWhitelist()
	if len(remaining) != 2 {
		t.Fatalf("ListWhitelist after prune len = %d, want 2", len(remaining))
	}

	if db.IsWhitelisted("192.168.1.3") {
		t.Fatal("expired entry should be gone after prune")
	}
	if !db.IsWhitelisted("192.168.1.1") {
		t.Fatal("permanent entry should still be whitelisted after prune")
	}
	if !db.IsWhitelisted("192.168.1.2") {
		t.Fatal("future entry should still be whitelisted after prune")
	}
}

func TestAllPermanentBlocks(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for _, ip := range ips {
		if err := db.AddPermanentBlock(ip, "test-reason"); err != nil {
			t.Fatalf("AddPermanentBlock(%s): %v", ip, err)
		}
	}

	blocks := db.AllPermanentBlocks()
	if len(blocks) != 3 {
		t.Fatalf("AllPermanentBlocks len = %d, want 3", len(blocks))
	}

	// Verify all IPs are present.
	found := make(map[string]bool)
	for _, b := range blocks {
		found[b.IP] = true
	}
	for _, ip := range ips {
		if !found[ip] {
			t.Fatalf("AllPermanentBlocks missing IP %s", ip)
		}
	}
}
