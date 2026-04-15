package threat

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

// TestLookupThreatDBBranchViaInit exercises the checks.GetThreatDB() != nil
// branch in Lookup. InitThreatDB uses sync.Once, so this only fires once per
// test binary; subsequent tests that need a nil ThreatDB cannot reset it, but
// we can still add our own IP via AddPermanent to drive the branch.
func TestLookupThreatDBBranchViaInit(t *testing.T) {
	dir := t.TempDir()
	tdb := checks.InitThreatDB(dir, nil)
	if tdb == nil {
		t.Skip("ThreatDB not initialized (sync.Once already fired elsewhere)")
	}

	// Seed a bbolt store so AddPermanent persists via bbolt path (best-effort).
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sdb.Close() }()
	store.SetGlobal(sdb)
	defer store.SetGlobal(nil)

	tdb.AddPermanent("198.51.100.5", "test-threatdb")

	intel := Lookup("198.51.100.5", dir)
	if intel == nil {
		t.Fatal("Lookup returned nil")
	}
	// With an InThreatDB hit, the unified score is floored to 100 → malicious.
	if !intel.InThreatDB {
		// InitThreatDB may already have been called by a prior test with a
		// different directory; skip rather than fail spuriously.
		t.Skip("ThreatDB not populated for this test's IP (shared global state)")
	}
	if intel.ThreatDBSource == "" {
		t.Error("ThreatDBSource should be set")
	}
	if intel.Verdict != "malicious" {
		t.Errorf("Verdict = %q, want malicious (InThreatDB floors score)", intel.Verdict)
	}
}

// TestLookupCombinesBboltReputationAndBlockAndLegacy exercises Lookup with
// bbolt-backed reputation + bbolt block + legacy blocked_ips.json coexisting.
func TestLookupCombinesBboltReputationAndBlockAndLegacy(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sdb.Close() }()
	store.SetGlobal(sdb)
	defer store.SetGlobal(nil)

	// bbolt reputation (high abuse score).
	_ = sdb.SetReputation("198.51.100.10", store.ReputationEntry{
		Score: 95, Category: "abuse", CheckedAt: time.Now(),
	})
	// bbolt firewall block (permanent).
	_ = sdb.BlockIP("198.51.100.10", "test-block", time.Time{})

	// Legacy blocked_ips.json with a DIFFERENT IP so both files are read.
	writeBlockedIPsFile(t, dir, []map[string]any{
		{
			"ip":         "198.51.100.11",
			"reason":     "legacy entry",
			"blocked_at": time.Now().Format(time.RFC3339Nano),
			"expires_at": time.Time{}.Format(time.RFC3339Nano),
		},
	})

	intel := Lookup("198.51.100.10", dir)
	if intel.AbuseScore != 95 {
		t.Errorf("AbuseScore = %d, want 95", intel.AbuseScore)
	}
	if !intel.CurrentlyBlocked {
		t.Error("expected CurrentlyBlocked")
	}
	if intel.Verdict != "blocked" {
		t.Errorf("Verdict = %q, want blocked", intel.Verdict)
	}

	// Second IP is only in legacy file.
	intel2 := Lookup("198.51.100.11", dir)
	if !intel2.CurrentlyBlocked {
		t.Error("legacy-only IP should still be blocked")
	}
	if intel2.BlockReason != "legacy entry" {
		t.Errorf("BlockReason = %q", intel2.BlockReason)
	}
}

// TestLookupMissingStatePathIsClean exercises the nil-globals, missing-files
// early-return paths without tripping any errors.
func TestLookupMissingStatePathIsClean(t *testing.T) {
	// Point at a path that does not exist — state readers must handle this.
	nonexistent := filepath.Join(t.TempDir(), "does-not-exist")
	intel := Lookup("198.51.100.99", nonexistent)
	if intel == nil {
		t.Fatal("Lookup returned nil")
	}
	if intel.CurrentlyBlocked {
		t.Error("missing state should not mark as blocked")
	}
	if intel.AbuseScore != -1 {
		t.Errorf("AbuseScore = %d, want -1 (uncached)", intel.AbuseScore)
	}
}

// TestLookupBatchWithBboltAndLegacyCombined covers LookupBatch branches that
// draw from both bbolt state and a legacy blocked_ips.json file.
func TestLookupBatchWithBboltAndLegacyCombined(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sdb.Close() }()
	store.SetGlobal(sdb)
	defer store.SetGlobal(nil)

	_ = sdb.BlockIP("198.51.100.20", "bbolt block", time.Time{})
	writeBlockedIPsFile(t, dir, []map[string]any{
		{
			"ip":         "198.51.100.21",
			"reason":     "legacy only",
			"blocked_at": time.Now().Format(time.RFC3339Nano),
			"expires_at": time.Time{}.Format(time.RFC3339Nano),
		},
	})

	results := LookupBatch([]string{"198.51.100.20", "198.51.100.21", "198.51.100.22"}, dir)
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if results[0].Verdict != "blocked" {
		t.Errorf("results[0] = %q, want blocked", results[0].Verdict)
	}
	if results[1].Verdict != "blocked" {
		t.Errorf("results[1] = %q, want blocked", results[1].Verdict)
	}
	if results[2].Verdict != "clean" {
		t.Errorf("results[2] = %q, want clean", results[2].Verdict)
	}
}

// TestLookupAbuseCacheMissSetsSentinelScore confirms that an IP absent from
// the abuse cache keeps AbuseScore at -1 while still using block state.
func TestLookupAbuseCacheMissSetsSentinelScore(t *testing.T) {
	dir := t.TempDir()
	// Write a cache file for some OTHER IP so loadFullAbuseCache yields a
	// non-empty map but the lookup IP is not in it.
	writeAbuseCacheFile(t, dir, map[string]map[string]any{
		"10.0.0.1": {
			"score":      50,
			"category":   "scan",
			"checked_at": time.Now().Format(time.RFC3339Nano),
		},
	})

	intel := Lookup("198.51.100.30", dir)
	if intel.AbuseScore != -1 {
		t.Errorf("AbuseScore = %d, want -1 when not in cache", intel.AbuseScore)
	}
	if intel.Verdict != "clean" {
		t.Errorf("Verdict = %q, want clean", intel.Verdict)
	}
}

// TestLookupMalformedBlockedIPsFileIsClean exercises the malformed JSON
// fallback path in loadFullBlockState driven via Lookup.
func TestLookupMalformedBlockedIPsFileIsClean(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "blocked_ips.json"), []byte("{broken"), 0644); err != nil {
		t.Fatal(err)
	}
	intel := Lookup("198.51.100.40", dir)
	if intel.CurrentlyBlocked {
		t.Error("malformed blocked_ips.json should not mark IP as blocked")
	}
	if intel.Verdict != "clean" {
		t.Errorf("Verdict = %q, want clean", intel.Verdict)
	}
}
