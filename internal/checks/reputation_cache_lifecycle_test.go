package checks

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// The bbolt-backed reputation cache lifecycle: cleanCache prunes the
// store, saveReputationCache flushes the cycle's changes. These tests pin
// the contract that eviction is final -- a save must never resurrect what
// the prune deleted -- and that a save only writes entries that actually
// changed since load. Regression: the save used to re-put the entire
// in-memory map (one write transaction per entry), so TTL/cap eviction
// never stuck and the bucket grew without bound.

func TestReputationCacheEvictionSticksAcrossSaveCycle(t *testing.T) {
	sdb := withGlobalStore(t)
	statePath := t.TempDir()

	if err := sdb.SetReputation("203.0.113.10", store.ReputationEntry{
		Score:     80,
		Category:  "botnet",
		CheckedAt: time.Now().Add(-(cacheExpiry + time.Hour)),
	}); err != nil {
		t.Fatalf("SetReputation expired: %v", err)
	}
	if err := sdb.SetReputation("203.0.113.11", store.ReputationEntry{
		Score:     10,
		Category:  "ISP",
		CheckedAt: time.Now(),
	}); err != nil {
		t.Fatalf("SetReputation fresh: %v", err)
	}

	// Mimic the tail of a CheckIPReputation cycle: load, prune, save.
	cache := loadReputationCache(statePath)
	if len(cache.Entries) != 2 {
		t.Fatalf("loaded %d entries, want 2", len(cache.Entries))
	}
	cleanCache(cache)
	saveReputationCache(statePath, cache)

	if _, ok := cache.Entries["203.0.113.10"]; ok {
		t.Error("expired entry still in in-memory cache after cleanCache")
	}
	if _, found := sdb.GetReputation("203.0.113.10"); found {
		t.Error("expired entry resurrected in store by the save cycle")
	}
	if _, found := sdb.GetReputation("203.0.113.11"); !found {
		t.Error("fresh entry lost from store")
	}
}

func TestSaveReputationCacheWritesOnlyChangedEntries(t *testing.T) {
	sdb := withGlobalStore(t)
	statePath := t.TempDir()

	if err := sdb.SetReputation("203.0.113.20", store.ReputationEntry{
		Score:     10,
		Category:  "ISP",
		CheckedAt: time.Now(),
	}); err != nil {
		t.Fatalf("SetReputation: %v", err)
	}
	if err := sdb.SetReputation("203.0.113.21", store.ReputationEntry{
		Score:     20,
		Category:  "Data Center",
		CheckedAt: time.Now(),
	}); err != nil {
		t.Fatalf("SetReputation: %v", err)
	}

	cache := loadReputationCache(statePath)
	if len(cache.Entries) != 2 {
		t.Fatalf("loaded %d entries, want 2", len(cache.Entries))
	}

	before := sdb.WriteTxID()
	saveReputationCache(statePath, cache)
	if got := sdb.WriteTxID(); got != before {
		t.Fatalf("save with no changes committed %d write txs, want 0", got-before)
	}

	cache.set("198.51.100.5", &reputationEntry{
		Score:     90,
		Category:  "Compromised Server",
		CheckedAt: time.Now(),
	})
	saveReputationCache(statePath, cache)
	if got := sdb.WriteTxID(); got != before+1 {
		t.Fatalf("save with one new entry committed %d write txs, want exactly 1", got-before)
	}
	got, found := sdb.GetReputation("198.51.100.5")
	if !found {
		t.Fatal("new entry not persisted")
	}
	if got.Score != 90 || got.Category != "Compromised Server" {
		t.Fatalf("persisted entry = %+v, want score 90 category %q", got, "Compromised Server")
	}

	// Change tracking must reset once flushed: a second save with no new
	// writes commits nothing.
	saveReputationCache(statePath, cache)
	if got := sdb.WriteTxID(); got != before+1 {
		t.Fatalf("second save re-wrote already-flushed entries (%d extra write txs)", got-before-1)
	}
}

func TestReputationCacheEntryUpdatedThenEvictedNotPersisted(t *testing.T) {
	sdb := withGlobalStore(t)
	statePath := t.TempDir()

	if err := sdb.SetReputation("203.0.113.30", store.ReputationEntry{
		Score:     20,
		Category:  "ISP",
		CheckedAt: time.Now(),
	}); err != nil {
		t.Fatalf("SetReputation: %v", err)
	}

	// Touched this cycle but already past TTL when eviction runs; eviction
	// must win over the pending write and delete any older stored value.
	cache := loadReputationCache(statePath)
	cache.set("203.0.113.30", &reputationEntry{
		Score:     80,
		Category:  "botnet",
		CheckedAt: time.Now().Add(-(cacheExpiry + time.Hour)),
	})

	cleanCache(cache)
	saveReputationCache(statePath, cache)

	if _, ok := cache.Entries["203.0.113.30"]; ok {
		t.Error("expired entry still in in-memory cache after cleanCache")
	}
	if _, found := sdb.GetReputation("203.0.113.30"); found {
		t.Error("evicted entry persisted to store by the save")
	}
}

func TestReputationCacheCapIncludesDirtyEntriesBeforeSave(t *testing.T) {
	sdb := withGlobalStore(t)
	statePath := t.TempDir()
	base := time.Now().Add(-2 * time.Hour)
	entries := make(map[string]store.ReputationEntry, maxCacheEntries)
	for i := 0; i < maxCacheEntries; i++ {
		ip := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		entries[ip] = store.ReputationEntry{
			Score:     10,
			Category:  "ISP",
			CheckedAt: base.Add(time.Duration(i) * time.Second),
		}
	}
	if err := sdb.SetReputationBatch(entries); err != nil {
		t.Fatalf("SetReputationBatch: %v", err)
	}

	cache := loadReputationCache(statePath)
	cache.set("203.0.113.250", &reputationEntry{
		Score:     90,
		Category:  "botnet",
		CheckedAt: time.Now(),
	})

	cleanCache(cache)
	saveReputationCache(statePath, cache)

	all := sdb.AllReputation()
	if got := len(all); got != maxCacheEntries {
		t.Fatalf("store reputation entries = %d, want %d", got, maxCacheEntries)
	}
	if _, found := all["203.0.113.250"]; !found {
		t.Fatal("dirty fresh entry missing after capped save")
	}
	if _, found := all["198.51.0.0"]; found {
		t.Fatal("oldest loaded entry survived cap after dirty save")
	}
}
