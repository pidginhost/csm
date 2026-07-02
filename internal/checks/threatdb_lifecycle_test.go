package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// These tests cover the temp-block lifecycle of the local threat DB: a
// temporary auto-block must not become a forever "known malicious IP"
// entry that re-flags the address on every access after the firewall
// block lapses (the production permablock loop).

func TestThreatDBLookupIgnoresLapsedTempEntry(t *testing.T) {
	db := newTestThreatDB(t)
	db.badIPs["192.0.2.40"] = "CSM auto-block: web attack"
	db.badIPExpiry["192.0.2.40"] = time.Now().Add(-time.Minute)

	if src, ok := db.Lookup("192.0.2.40"); ok {
		t.Fatalf("lapsed temp entry still flagged: (%q, %v)", src, ok)
	}

	db.badIPExpiry["192.0.2.40"] = time.Now().Add(time.Minute)
	if _, ok := db.Lookup("192.0.2.40"); !ok {
		t.Fatal("live temp entry should flag")
	}
}

func TestThreatDBLookupFallsBackToFeedWhenTempEntryLapses(t *testing.T) {
	db := newTestThreatDB(t)
	db.badIPs["192.0.2.41"] = "CSM auto-block: web attack"
	db.badIPExpiry["192.0.2.41"] = time.Now().Add(-time.Minute)
	db.feedIPs = map[string]map[string]struct{}{
		"cins-army": {"192.0.2.41": {}},
	}

	src, ok := db.Lookup("192.0.2.41")
	if !ok || src != "cins-army" {
		t.Fatalf("Lookup with lapsed temp plus feed = (%q, %v), want (cins-army, true)", src, ok)
	}
}

func TestThreatDBAddTemporaryPersistsExpiringEntry(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)

	before := time.Now()
	db.AddTemporary("192.0.2.41", "web attack", time.Hour)

	if src, ok := db.Lookup("192.0.2.41"); !ok || src != "web attack" {
		t.Fatalf("Lookup after AddTemporary = (%q, %v)", src, ok)
	}

	entry, found := store.Global().GetPermanentBlock("192.0.2.41")
	if !found {
		t.Fatal("store entry missing after AddTemporary")
	}
	if entry.Source != store.ThreatSourceAutoBlock {
		t.Fatalf("Source = %q, want %q", entry.Source, store.ThreatSourceAutoBlock)
	}
	if entry.ExpiresAt.Before(before.Add(50*time.Minute)) || entry.ExpiresAt.After(before.Add(70*time.Minute)) {
		t.Fatalf("ExpiresAt = %v, want ~1h from %v", entry.ExpiresAt, before)
	}
}

func TestThreatDBAddTemporaryKeepsStrongerEvidence(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)

	// Feed-listed IP: the feed is independent permanent evidence; a temp
	// block on top must not attach an expiry that later hides it.
	db.badIPs["192.0.2.42"] = "spamhaus-drop"
	db.AddTemporary("192.0.2.42", "web attack", time.Hour)

	if src, _ := db.Lookup("192.0.2.42"); src != "spamhaus-drop" {
		t.Fatalf("feed ownership lost: %q", src)
	}
	if _, ok := db.badIPExpiry["192.0.2.42"]; ok {
		t.Fatal("expiry attached to feed-owned entry")
	}
	if _, found := store.Global().GetPermanentBlock("192.0.2.42"); found {
		t.Fatal("temp store row written over stronger in-memory evidence")
	}
}

func TestThreatDBRemovePermanentClearsExpiry(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)

	db.AddTemporary("192.0.2.43", "web attack", time.Hour)
	db.RemovePermanent("192.0.2.43")

	if _, ok := db.Lookup("192.0.2.43"); ok {
		t.Fatal("removed IP still flagged")
	}
	if _, ok := db.badIPExpiry["192.0.2.43"]; ok {
		t.Fatal("expiry metadata survived RemovePermanent")
	}
}

func TestLoadPermanentBlocklistSkipsExpiredRows(t *testing.T) {
	withTestThreatStore(t)
	now := time.Now()

	sdb := store.Global()
	if err := sdb.AddTempBlock("192.0.2.44", "web attack", now.Add(time.Hour)); err != nil {
		t.Fatalf("AddTempBlock(live): %v", err)
	}
	if err := sdb.AddTempBlock("192.0.2.45", "web attack", now.Add(-time.Hour)); err != nil {
		t.Fatalf("AddTempBlock(expired): %v", err)
	}
	if err := sdb.AddPermanentBlock("192.0.2.46", "operator block"); err != nil {
		t.Fatalf("AddPermanentBlock: %v", err)
	}

	db := newTestThreatDB(t)
	db.loadPermanentBlocklist()

	if _, ok := db.Lookup("192.0.2.44"); !ok {
		t.Fatal("live temp row not loaded")
	}
	if exp, ok := db.badIPExpiry["192.0.2.44"]; !ok || !exp.Equal(now.Add(time.Hour)) {
		t.Fatalf("live temp expiry not loaded: (%v, %v)", exp, ok)
	}
	if _, ok := db.Lookup("192.0.2.45"); ok {
		t.Fatal("expired temp row loaded: permablock loop would resume")
	}
	if _, ok := db.Lookup("192.0.2.46"); !ok {
		t.Fatal("operator row not loaded")
	}
	if db.PermanentCount != 2 {
		t.Fatalf("PermanentCount = %d, want 2", db.PermanentCount)
	}
}

func TestThreatDBPruneExpiredThreats(t *testing.T) {
	withTestThreatStore(t)
	now := time.Now()

	sdb := store.Global()
	if err := sdb.AddTempBlock("192.0.2.47", "web attack", now.Add(-time.Hour)); err != nil {
		t.Fatalf("AddTempBlock: %v", err)
	}
	if err := sdb.AddTempBlock("192.0.2.48", "web attack", now.Add(-time.Hour)); err != nil {
		t.Fatalf("AddTempBlock: %v", err)
	}

	db := newTestThreatDB(t)
	// Lapsed temp entries still sitting in memory; .48 is also listed by a
	// feed, so pruning must hand ownership back to the feed instead of
	// dropping the IP until the next feed rebuild.
	db.badIPs["192.0.2.47"] = "web attack"
	db.badIPExpiry["192.0.2.47"] = now.Add(-time.Hour)
	db.badIPs["192.0.2.48"] = "web attack"
	db.badIPExpiry["192.0.2.48"] = now.Add(-time.Hour)
	db.feedIPs = map[string]map[string]struct{}{
		"cins-army": {"192.0.2.48": {}},
	}

	if removed := db.PruneExpiredThreats(); removed != 2 {
		t.Fatalf("PruneExpiredThreats = %d, want 2", removed)
	}

	if _, ok := db.Lookup("192.0.2.47"); ok {
		t.Fatal("lapsed entry survived prune")
	}
	if src, ok := db.Lookup("192.0.2.48"); !ok || src != "cins-army" {
		t.Fatalf("feed ownership not restored: (%q, %v)", src, ok)
	}
	if len(db.badIPExpiry) != 0 {
		t.Fatalf("expiry map not cleaned: %v", db.badIPExpiry)
	}
	if _, found := sdb.GetPermanentBlock("192.0.2.47"); found {
		t.Fatal("store row survived prune")
	}
	if _, found := sdb.GetPermanentBlock("192.0.2.48"); found {
		t.Fatal("store row survived prune")
	}
}
