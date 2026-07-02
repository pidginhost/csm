package store

import (
	"encoding/json"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestAddRemovePermanent(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

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

	// Lookup one - found with correct reason.
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

	// Lookup removed IP - not found.
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
	defer func() { _ = db.Close() }()

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

	// Prune - should remove 1 expired entry.
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

func TestAddTempBlockCarriesExpiryAndPrunes(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now()
	if err := db.AddTempBlock("192.0.2.10", "web_attack: brute force", now.Add(1*time.Hour)); err != nil {
		t.Fatalf("AddTempBlock(live): %v", err)
	}
	if err := db.AddTempBlock("192.0.2.11", "web_attack: brute force", now.Add(-1*time.Hour)); err != nil {
		t.Fatalf("AddTempBlock(expired): %v", err)
	}
	if err := db.AddPermanentBlock("192.0.2.12", "operator block"); err != nil {
		t.Fatalf("AddPermanentBlock: %v", err)
	}

	live, found := db.GetPermanentBlock("192.0.2.10")
	if !found {
		t.Fatal("GetPermanentBlock(192.0.2.10): not found")
	}
	if live.Source != ThreatSourceAutoBlock {
		t.Fatalf("Source = %q, want %q", live.Source, ThreatSourceAutoBlock)
	}
	if !live.ExpiresAt.Equal(now.Add(1 * time.Hour)) {
		t.Fatalf("ExpiresAt = %v, want %v", live.ExpiresAt, now.Add(1*time.Hour))
	}
	if live.Expired(now) {
		t.Fatal("live temp entry reported expired")
	}

	lapsed, found := db.GetPermanentBlock("192.0.2.11")
	if !found {
		t.Fatal("GetPermanentBlock(192.0.2.11): not found")
	}
	if !lapsed.Expired(now) {
		t.Fatal("lapsed temp entry not reported expired")
	}

	operator, found := db.GetPermanentBlock("192.0.2.12")
	if !found {
		t.Fatal("GetPermanentBlock(192.0.2.12): not found")
	}
	if operator.Source != ThreatSourceOperator {
		t.Fatalf("operator Source = %q, want %q", operator.Source, ThreatSourceOperator)
	}
	if operator.Expired(now.Add(1000 * time.Hour)) {
		t.Fatal("operator entry must never expire")
	}

	if removed := db.PruneExpiredThreats(); removed != 1 {
		t.Fatalf("PruneExpiredThreats = %d, want 1", removed)
	}
	if _, found := db.GetPermanentBlock("192.0.2.11"); found {
		t.Fatal("expired temp entry survived prune")
	}
	if _, found := db.GetPermanentBlock("192.0.2.10"); !found {
		t.Fatal("live temp entry deleted by prune")
	}
	if _, found := db.GetPermanentBlock("192.0.2.12"); !found {
		t.Fatal("operator entry deleted by prune")
	}
	if count := db.getCounter("threats:count"); count != 2 {
		t.Fatalf("threats:count after prune = %d, want 2", count)
	}
}

func TestAddTempBlockDoesNotDowngradePermanentRow(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now()

	// Operator row must survive a later temp write untouched.
	if err := db.AddPermanentBlock("192.0.2.20", "operator block"); err != nil {
		t.Fatalf("AddPermanentBlock: %v", err)
	}
	if err := db.AddTempBlock("192.0.2.20", "web_attack", now.Add(-1*time.Hour)); err != nil {
		t.Fatalf("AddTempBlock over operator row: %v", err)
	}
	entry, _ := db.GetPermanentBlock("192.0.2.20")
	if entry.Source != ThreatSourceOperator || !entry.ExpiresAt.IsZero() {
		t.Fatalf("operator row downgraded: %+v", entry)
	}

	// A later operator add upgrades a temp row to permanent.
	if err := db.AddTempBlock("192.0.2.21", "web_attack", now.Add(1*time.Hour)); err != nil {
		t.Fatalf("AddTempBlock: %v", err)
	}
	if err := db.AddPermanentBlock("192.0.2.21", "operator block"); err != nil {
		t.Fatalf("AddPermanentBlock over temp row: %v", err)
	}
	entry, _ = db.GetPermanentBlock("192.0.2.21")
	if entry.Source != ThreatSourceOperator || !entry.ExpiresAt.IsZero() {
		t.Fatalf("temp row not upgraded to operator: %+v", entry)
	}

	// Re-blocking extends the expiry; a shorter expiry never truncates it.
	far := now.Add(3 * time.Hour)
	if err := db.AddTempBlock("192.0.2.22", "web_attack", far); err != nil {
		t.Fatalf("AddTempBlock(far): %v", err)
	}
	if err := db.AddTempBlock("192.0.2.22", "web_attack again", now.Add(1*time.Hour)); err != nil {
		t.Fatalf("AddTempBlock(near): %v", err)
	}
	entry, _ = db.GetPermanentBlock("192.0.2.22")
	if !entry.ExpiresAt.Equal(far) {
		t.Fatalf("expiry truncated: got %v, want %v", entry.ExpiresAt, far)
	}
	if err := db.AddTempBlock("192.0.2.22", "web_attack later", now.Add(5*time.Hour)); err != nil {
		t.Fatalf("AddTempBlock(later): %v", err)
	}
	entry, _ = db.GetPermanentBlock("192.0.2.22")
	if !entry.ExpiresAt.Equal(now.Add(5 * time.Hour)) {
		t.Fatalf("expiry not extended: got %v", entry.ExpiresAt)
	}

	// Counter counts unique IPs, not writes.
	if count := db.getCounter("threats:count"); count != 3 {
		t.Fatalf("threats:count = %d, want 3", count)
	}
}

// TestPruneExpiredThreatsClassifiesLegacyRows reproduces the production
// permablock loop: rows written by the pre-fix temp auto-block path carry
// no source and no expiry, so they lived forever and re-flagged the IP on
// every access. Legacy rows must converge out (pruned) while legacy
// operator rows (identified by the only two reason strings the Web UI ever
// wrote) survive.
func TestPruneExpiredThreatsClassifiesLegacyRows(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	legacy := map[string]string{
		"192.0.2.30": "WordPress brute force from 192.0.2.30",
		"192.0.2.31": "Manually blocked via CSM Web UI",
		"192.0.2.32": "Bulk blocked via CSM Web UI [2026-01-02]",
	}
	err = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threats"))
		for ip, reason := range legacy {
			val, merr := json.Marshal(map[string]interface{}{
				"ip":         ip,
				"reason":     reason,
				"blocked_at": time.Now().Add(-30 * 24 * time.Hour),
			})
			if merr != nil {
				return merr
			}
			if perr := b.Put([]byte(ip), val); perr != nil {
				return perr
			}
		}
		return setCounter(tx, "threats:count", len(legacy))
	})
	if err != nil {
		t.Fatalf("seeding legacy rows: %v", err)
	}

	if removed := db.PruneExpiredThreats(); removed != 1 {
		t.Fatalf("PruneExpiredThreats = %d, want 1", removed)
	}
	if _, found := db.GetPermanentBlock("192.0.2.30"); found {
		t.Fatal("legacy auto-block row survived prune")
	}
	if _, found := db.GetPermanentBlock("192.0.2.31"); !found {
		t.Fatal("legacy manual row deleted by prune")
	}
	if _, found := db.GetPermanentBlock("192.0.2.32"); !found {
		t.Fatal("legacy migrated bulk row deleted by prune")
	}
	if count := db.getCounter("threats:count"); count != 2 {
		t.Fatalf("threats:count after prune = %d, want 2", count)
	}
}

func TestAllPermanentBlocks(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

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
