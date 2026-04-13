package threat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// --- computeVerdict: additional edge cases --------------------------------

func TestComputeVerdictAbuseScoreNegativeIgnored(t *testing.T) {
	intel := &IPIntelligence{LocalScore: 20, AbuseScore: -1}
	computeVerdict(intel)
	// -1 (not cached) should not influence the unified score.
	if intel.UnifiedScore != 20 {
		t.Errorf("UnifiedScore = %d, want 20 (-1 abuse should not contribute)", intel.UnifiedScore)
	}
	if intel.Verdict != "clean" {
		t.Errorf("Verdict = %q, want clean", intel.Verdict)
	}
}

func TestComputeVerdictLocalScoreExactly39(t *testing.T) {
	intel := &IPIntelligence{LocalScore: 39, AbuseScore: -1}
	computeVerdict(intel)
	if intel.Verdict != "clean" {
		t.Errorf("score=39 -> Verdict = %q, want clean", intel.Verdict)
	}
}

func TestComputeVerdictLocalScoreExactly79(t *testing.T) {
	intel := &IPIntelligence{LocalScore: 79, AbuseScore: -1}
	computeVerdict(intel)
	if intel.Verdict != "suspicious" {
		t.Errorf("score=79 -> Verdict = %q, want suspicious", intel.Verdict)
	}
}

func TestComputeVerdictBlockedOverridesMalicious(t *testing.T) {
	intel := &IPIntelligence{LocalScore: 100, AbuseScore: 100, CurrentlyBlocked: true}
	computeVerdict(intel)
	if intel.Verdict != "blocked" {
		t.Errorf("blocked + score=100 -> Verdict = %q, want blocked", intel.Verdict)
	}
}

func TestComputeVerdictThreatDBAlreadyAt100(t *testing.T) {
	intel := &IPIntelligence{LocalScore: 100, AbuseScore: -1, InThreatDB: true}
	computeVerdict(intel)
	if intel.UnifiedScore != 100 {
		t.Errorf("UnifiedScore should stay at 100, got %d", intel.UnifiedScore)
	}
}

func TestComputeVerdictZeroScoresClean(t *testing.T) {
	intel := &IPIntelligence{LocalScore: 0, AbuseScore: 0}
	computeVerdict(intel)
	if intel.Verdict != "clean" {
		t.Errorf("Verdict = %q, want clean", intel.Verdict)
	}
	if intel.UnifiedScore != 0 {
		t.Errorf("UnifiedScore = %d, want 0", intel.UnifiedScore)
	}
}

// --- applyBlockState: year <= 1 edge case for expiresAt ------------------

func TestApplyBlockStateExpiresAtYearOne(t *testing.T) {
	intel := &IPIntelligence{IP: "1.2.3.4"}
	// Year=1 is the zero-ish value that bbolt might store.
	expiresAt := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	entries := map[string]*blockEntry{
		"1.2.3.4": {
			reason:    "permanent-ish",
			blockedAt: time.Now(),
			expiresAt: expiresAt,
			permanent: true,
		},
	}
	applyBlockState(intel, entries)
	if intel.BlockExpiresAt != nil {
		t.Error("year <= 1 should not set BlockExpiresAt")
	}
	if !intel.BlockPermanent {
		t.Error("should be marked permanent")
	}
}

// --- loadFullAbuseCache: bbolt with expired entries -----------------------

func TestLoadFullAbuseCacheViaBboltSkipsExpired(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sdb.Close() }()
	store.SetGlobal(sdb)
	defer store.SetGlobal(nil)

	oldTime := time.Now().Add(-12 * time.Hour)
	_ = sdb.SetReputation("203.0.113.50", store.ReputationEntry{
		Score: 80, Category: "old", CheckedAt: oldTime,
	})
	_ = sdb.SetReputation("203.0.113.51", store.ReputationEntry{
		Score: 60, Category: "fresh", CheckedAt: time.Now(),
	})

	cache := loadFullAbuseCache(dir)
	if _, ok := cache["203.0.113.50"]; ok {
		t.Error("expired entry should be dropped from bbolt cache")
	}
	if entry, ok := cache["203.0.113.51"]; !ok || entry.Score != 60 {
		t.Errorf("fresh entry missing or wrong: %+v", entry)
	}
}

// --- loadFullAbuseCache: bbolt with negative score -----------------------

func TestLoadFullAbuseCacheViaBboltSkipsNegativeScore(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sdb.Close() }()
	store.SetGlobal(sdb)
	defer store.SetGlobal(nil)

	_ = sdb.SetReputation("203.0.113.60", store.ReputationEntry{
		Score: -1, Category: "error", CheckedAt: time.Now(),
	})

	cache := loadFullAbuseCache(dir)
	if _, ok := cache["203.0.113.60"]; ok {
		t.Error("negative score should be dropped from bbolt cache")
	}
}

// --- loadFullBlockState: bbolt with multiple entries ---------------------

func TestLoadFullBlockStateViaBboltMultipleEntries(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sdb.Close() }()
	store.SetGlobal(sdb)
	defer store.SetGlobal(nil)

	_ = sdb.BlockIP("10.0.0.1", "brute", time.Time{})
	_ = sdb.BlockIP("10.0.0.2", "rate limit", time.Now().Add(24*time.Hour))

	blocks := loadFullBlockState(dir)
	if len(blocks) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(blocks))
	}
	if !blocks["10.0.0.1"].permanent {
		t.Error("10.0.0.1 should be permanent")
	}
	if blocks["10.0.0.2"].permanent {
		t.Error("10.0.0.2 should not be permanent")
	}
}

// --- loadFullBlockState: legacy blocked_ips.json deduplication -----------

func TestLoadFullBlockStateLegacyDoesNotOverrideBbolt(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sdb.Close() }()
	store.SetGlobal(sdb)
	defer store.SetGlobal(nil)

	// Block via bbolt.
	_ = sdb.BlockIP("203.0.113.70", "bbolt reason", time.Time{})

	// Also write a legacy file with the same IP but different reason.
	writeBlockedIPsFile(t, dir, []map[string]any{
		{
			"ip":         "203.0.113.70",
			"reason":     "legacy reason",
			"blocked_at": time.Now().Format(time.RFC3339Nano),
			"expires_at": time.Time{}.Format(time.RFC3339Nano),
		},
	})

	blocks := loadFullBlockState(dir)
	entry, ok := blocks["203.0.113.70"]
	if !ok {
		t.Fatal("expected 203.0.113.70 in block map")
	}
	// bbolt entry should take precedence.
	if entry.reason != "bbolt reason" {
		t.Errorf("reason = %q, want 'bbolt reason' (bbolt takes precedence)", entry.reason)
	}
}

// --- loadFullBlockState: legacy only (no bbolt) --------------------------

func TestLoadFullBlockStateLegacyOnlyActive(t *testing.T) {
	state := t.TempDir()
	future := time.Now().Add(24 * time.Hour)
	writeBlockedIPsFile(t, state, []map[string]any{
		{
			"ip":         "203.0.113.80",
			"reason":     "legacy active",
			"blocked_at": time.Now().Format(time.RFC3339Nano),
			"expires_at": future.Format(time.RFC3339Nano),
		},
	})

	got := loadFullBlockState(state)
	entry, ok := got["203.0.113.80"]
	if !ok {
		t.Fatal("expected 203.0.113.80 from legacy file")
	}
	if entry.permanent {
		t.Error("should not be permanent (has future expiry)")
	}
}

// --- LookupBatch: all blocked IPs ----------------------------------------

func TestLookupBatchAllBlocked(t *testing.T) {
	state := t.TempDir()
	writeBlockedIPsFile(t, state, []map[string]any{
		{
			"ip":         "1.1.1.1",
			"reason":     "blocked",
			"blocked_at": time.Now().Format(time.RFC3339Nano),
			"expires_at": time.Time{}.Format(time.RFC3339Nano),
		},
		{
			"ip":         "2.2.2.2",
			"reason":     "blocked too",
			"blocked_at": time.Now().Format(time.RFC3339Nano),
			"expires_at": time.Time{}.Format(time.RFC3339Nano),
		},
	})

	results := LookupBatch([]string{"1.1.1.1", "2.2.2.2"}, state)
	for i, r := range results {
		if r.Verdict != "blocked" {
			t.Errorf("results[%d].Verdict = %q, want blocked", i, r.Verdict)
		}
		if !r.CurrentlyBlocked {
			t.Errorf("results[%d] should be blocked", i)
		}
	}
}

// --- LookupBatch via bbolt -----------------------------------------------

func TestLookupBatchViaBbolt(t *testing.T) {
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sdb.Close() }()
	store.SetGlobal(sdb)
	defer store.SetGlobal(nil)

	_ = sdb.SetReputation("10.0.0.1", store.ReputationEntry{
		Score: 50, Category: "scan", CheckedAt: time.Now(),
	})
	_ = sdb.BlockIP("10.0.0.2", "malicious", time.Time{})

	results := LookupBatch([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, dir)
	if len(results) != 3 {
		t.Fatalf("got %d, want 3", len(results))
	}
	if results[0].AbuseScore != 50 {
		t.Errorf("results[0].AbuseScore = %d, want 50", results[0].AbuseScore)
	}
	if results[0].Verdict != "suspicious" {
		t.Errorf("results[0].Verdict = %q, want suspicious", results[0].Verdict)
	}
	if results[1].Verdict != "blocked" {
		t.Errorf("results[1].Verdict = %q, want blocked", results[1].Verdict)
	}
	if results[2].Verdict != "clean" {
		t.Errorf("results[2].Verdict = %q, want clean", results[2].Verdict)
	}
}

// --- Lookup with both abuse cache and block state from flat files --------

func TestLookupCombinesAbuseAndBlock(t *testing.T) {
	state := t.TempDir()
	writeAbuseCacheFile(t, state, map[string]map[string]any{
		"203.0.113.90": {
			"score":      95,
			"category":   "DDoS",
			"checked_at": time.Now().Format(time.RFC3339Nano),
		},
	})
	writeBlockedIPsFile(t, state, []map[string]any{
		{
			"ip":         "203.0.113.90",
			"reason":     "blocked for DDoS",
			"blocked_at": time.Now().Format(time.RFC3339Nano),
			"expires_at": time.Time{}.Format(time.RFC3339Nano),
		},
	})

	intel := Lookup("203.0.113.90", state)
	if intel.AbuseScore != 95 {
		t.Errorf("AbuseScore = %d, want 95", intel.AbuseScore)
	}
	if !intel.CurrentlyBlocked {
		t.Error("should be blocked")
	}
	// blocked overrides malicious.
	if intel.Verdict != "blocked" {
		t.Errorf("Verdict = %q, want blocked (overrides malicious)", intel.Verdict)
	}
}

// --- loadFullAbuseCache: flat file with multiple entries ------------------

func TestLoadFullAbuseCacheFlatFileMultipleEntries(t *testing.T) {
	state := t.TempDir()
	now := time.Now()
	body := map[string]map[string]any{
		"1.1.1.1": {"score": 50, "category": "scan", "checked_at": now.Format(time.RFC3339Nano)},
		"2.2.2.2": {"score": 90, "category": "brute", "checked_at": now.Format(time.RFC3339Nano)},
		"3.3.3.3": {"score": -1, "category": "error", "checked_at": now.Format(time.RFC3339Nano)}, // should be skipped
	}
	writeAbuseCacheFile(t, state, body)

	got := loadFullAbuseCache(state)
	if len(got) != 2 {
		t.Errorf("expected 2 entries (skip negative), got %d", len(got))
	}
	if got["1.1.1.1"].Score != 50 {
		t.Errorf("1.1.1.1 Score = %d, want 50", got["1.1.1.1"].Score)
	}
	if got["2.2.2.2"].Score != 90 {
		t.Errorf("2.2.2.2 Score = %d, want 90", got["2.2.2.2"].Score)
	}
}

// --- loadFullBlockState: empty legacy file --------------------------------

func TestLoadFullBlockStateEmptyLegacyFile(t *testing.T) {
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "blocked_ips.json"), []byte(`{"ips":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	got := loadFullBlockState(state)
	if len(got) != 0 {
		t.Errorf("empty legacy file should yield empty map, got %+v", got)
	}
}

// --- loadFullBlockState: legacy with year-1 expiresAt --------------------

func TestLoadFullBlockStateLegacyPermanentViaYearOne(t *testing.T) {
	state := t.TempDir()
	// Year=1 in JSON
	yearOne := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	ips := []map[string]any{
		{
			"ip":         "203.0.113.99",
			"reason":     "permanent via year1",
			"blocked_at": time.Now().Format(time.RFC3339Nano),
			"expires_at": yearOne.Format(time.RFC3339Nano),
		},
	}
	data, _ := json.Marshal(map[string]any{"ips": ips})
	if err := os.WriteFile(filepath.Join(state, "blocked_ips.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	got := loadFullBlockState(state)
	entry, ok := got["203.0.113.99"]
	if !ok {
		t.Fatal("expected 203.0.113.99")
	}
	if !entry.permanent {
		t.Error("year-1 expiresAt should be marked permanent")
	}
}
