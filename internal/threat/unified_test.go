package threat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- computeVerdict ----------------------------------------------------

func TestComputeVerdictClean(t *testing.T) {
	intel := &IPIntelligence{LocalScore: 0, AbuseScore: -1}
	computeVerdict(intel)
	if intel.Verdict != "clean" {
		t.Errorf("Verdict = %q, want clean", intel.Verdict)
	}
	if intel.UnifiedScore != 0 {
		t.Errorf("UnifiedScore = %d, want 0", intel.UnifiedScore)
	}
}

func TestComputeVerdictSuspiciousFromLocal(t *testing.T) {
	intel := &IPIntelligence{LocalScore: 50, AbuseScore: 10}
	computeVerdict(intel)
	if intel.Verdict != "suspicious" {
		t.Errorf("Verdict = %q, want suspicious", intel.Verdict)
	}
	if intel.UnifiedScore != 50 {
		t.Errorf("UnifiedScore = %d, want 50 (local beats abuse)", intel.UnifiedScore)
	}
}

func TestComputeVerdictMaliciousFromAbuse(t *testing.T) {
	intel := &IPIntelligence{LocalScore: 30, AbuseScore: 90}
	computeVerdict(intel)
	if intel.Verdict != "malicious" {
		t.Errorf("Verdict = %q, want malicious", intel.Verdict)
	}
	if intel.UnifiedScore != 90 {
		t.Errorf("UnifiedScore = %d, want 90 (abuse beats local)", intel.UnifiedScore)
	}
}

func TestComputeVerdictThreatDBFloorsScoreToMalicious(t *testing.T) {
	intel := &IPIntelligence{LocalScore: 10, AbuseScore: -1, InThreatDB: true}
	computeVerdict(intel)
	if intel.UnifiedScore != 100 {
		t.Errorf("ThreatDB-listed IP should get UnifiedScore >= 100, got %d", intel.UnifiedScore)
	}
	if intel.Verdict != "malicious" {
		t.Errorf("Verdict = %q, want malicious", intel.Verdict)
	}
}

func TestComputeVerdictThreatDBWithHigherExistingScore(t *testing.T) {
	// A ThreatDB listing should not demote an already-higher score.
	intel := &IPIntelligence{LocalScore: 150, AbuseScore: -1, InThreatDB: true}
	computeVerdict(intel)
	if intel.UnifiedScore != 150 {
		t.Errorf("UnifiedScore should stay at 150, got %d", intel.UnifiedScore)
	}
}

func TestComputeVerdictBlockedBeatsEverything(t *testing.T) {
	intel := &IPIntelligence{LocalScore: 0, AbuseScore: -1, CurrentlyBlocked: true}
	computeVerdict(intel)
	if intel.Verdict != "blocked" {
		t.Errorf("Verdict = %q, want blocked", intel.Verdict)
	}
}

func TestComputeVerdictBoundaries(t *testing.T) {
	// Exactly at the suspicious threshold.
	intel := &IPIntelligence{LocalScore: 40}
	computeVerdict(intel)
	if intel.Verdict != "suspicious" {
		t.Errorf("score=40 -> Verdict = %q, want suspicious", intel.Verdict)
	}

	// Exactly at the malicious threshold.
	intel = &IPIntelligence{LocalScore: 80}
	computeVerdict(intel)
	if intel.Verdict != "malicious" {
		t.Errorf("score=80 -> Verdict = %q, want malicious", intel.Verdict)
	}
}

// --- applyBlockState ---------------------------------------------------

func TestApplyBlockStateMiss(t *testing.T) {
	intel := &IPIntelligence{IP: "1.2.3.4"}
	applyBlockState(intel, map[string]*blockEntry{})
	if intel.CurrentlyBlocked {
		t.Error("unknown IP should not be marked blocked")
	}
}

func TestApplyBlockStatePermanent(t *testing.T) {
	intel := &IPIntelligence{IP: "1.2.3.4"}
	blockedAt := time.Date(2026, 4, 11, 10, 0, 0, 0, time.UTC)
	entries := map[string]*blockEntry{
		"1.2.3.4": {
			reason:    "brute force",
			blockedAt: blockedAt,
			permanent: true,
		},
	}
	applyBlockState(intel, entries)
	if !intel.CurrentlyBlocked {
		t.Error("IP should be marked blocked")
	}
	if intel.BlockReason != "brute force" {
		t.Errorf("BlockReason = %q", intel.BlockReason)
	}
	if !intel.BlockPermanent {
		t.Error("BlockPermanent should be true")
	}
	if intel.BlockedAt == nil || !intel.BlockedAt.Equal(blockedAt) {
		t.Errorf("BlockedAt = %v, want %v", intel.BlockedAt, blockedAt)
	}
	if intel.BlockExpiresAt != nil {
		t.Error("permanent block should not set BlockExpiresAt")
	}
}

func TestApplyBlockStateTemporary(t *testing.T) {
	intel := &IPIntelligence{IP: "5.6.7.8"}
	blockedAt := time.Date(2026, 4, 11, 10, 0, 0, 0, time.UTC)
	expiresAt := blockedAt.Add(24 * time.Hour)
	entries := map[string]*blockEntry{
		"5.6.7.8": {
			reason:    "rate limit",
			blockedAt: blockedAt,
			expiresAt: expiresAt,
		},
	}
	applyBlockState(intel, entries)
	if intel.BlockExpiresAt == nil || !intel.BlockExpiresAt.Equal(expiresAt) {
		t.Errorf("BlockExpiresAt = %v, want %v", intel.BlockExpiresAt, expiresAt)
	}
	if intel.BlockPermanent {
		t.Error("temporary block should not set BlockPermanent")
	}
}

func TestApplyBlockStateZeroTimesNotSet(t *testing.T) {
	intel := &IPIntelligence{IP: "9.9.9.9"}
	entries := map[string]*blockEntry{
		"9.9.9.9": {
			reason:    "x",
			blockedAt: time.Time{}, // zero
			expiresAt: time.Time{}, // zero
		},
	}
	applyBlockState(intel, entries)
	if intel.BlockedAt != nil {
		t.Errorf("BlockedAt should stay nil when entry.blockedAt is zero, got %v", intel.BlockedAt)
	}
	if intel.BlockExpiresAt != nil {
		t.Errorf("BlockExpiresAt should stay nil when entry.expiresAt is zero, got %v", intel.BlockExpiresAt)
	}
}

// --- loadFullAbuseCache ------------------------------------------------

func writeAbuseCacheFile(t *testing.T, statePath string, body map[string]map[string]any) {
	t.Helper()
	if err := os.MkdirAll(statePath, 0755); err != nil {
		t.Fatal(err)
	}
	wrapper := map[string]any{"entries": body}
	data, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statePath, "reputation_cache.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFullAbuseCacheMissingFileIsEmpty(t *testing.T) {
	got := loadFullAbuseCache(filepath.Join(t.TempDir(), "never"))
	if len(got) != 0 {
		t.Errorf("missing cache file should yield empty map, got %+v", got)
	}
}

func TestLoadFullAbuseCacheFresh(t *testing.T) {
	state := t.TempDir()
	now := time.Now()
	body := map[string]map[string]any{
		"1.2.3.4": {
			"score":      75,
			"category":   "scan",
			"checked_at": now.Format(time.RFC3339Nano),
		},
	}
	writeAbuseCacheFile(t, state, body)

	got := loadFullAbuseCache(state)
	entry, ok := got["1.2.3.4"]
	if !ok {
		t.Fatal("fresh entry missing")
	}
	if entry.Score != 75 {
		t.Errorf("Score = %d, want 75", entry.Score)
	}
	if entry.Category != "scan" {
		t.Errorf("Category = %q, want scan", entry.Category)
	}
}

func TestLoadFullAbuseCacheExpired(t *testing.T) {
	state := t.TempDir()
	old := time.Now().Add(-12 * time.Hour) // outside 6h window
	body := map[string]map[string]any{
		"1.2.3.4": {
			"score":      75,
			"category":   "scan",
			"checked_at": old.Format(time.RFC3339Nano),
		},
	}
	writeAbuseCacheFile(t, state, body)
	got := loadFullAbuseCache(state)
	if _, ok := got["1.2.3.4"]; ok {
		t.Error("expired entry should be dropped")
	}
}

func TestLoadFullAbuseCacheNegativeScoreSkipped(t *testing.T) {
	state := t.TempDir()
	body := map[string]map[string]any{
		"1.2.3.4": {
			"score":      -1,
			"category":   "error",
			"checked_at": time.Now().Format(time.RFC3339Nano),
		},
	}
	writeAbuseCacheFile(t, state, body)
	got := loadFullAbuseCache(state)
	if _, ok := got["1.2.3.4"]; ok {
		t.Error("negative score sentinel should be dropped")
	}
}

func TestLoadFullAbuseCacheMalformedJSON(t *testing.T) {
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "reputation_cache.json"), []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	got := loadFullAbuseCache(state)
	if len(got) != 0 {
		t.Errorf("malformed JSON should yield empty map, got %+v", got)
	}
}

func TestLoadFullAbuseCacheEmptyEntries(t *testing.T) {
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "reputation_cache.json"), []byte(`{"entries":null}`), 0644); err != nil {
		t.Fatal(err)
	}
	got := loadFullAbuseCache(state)
	if len(got) != 0 {
		t.Error("null entries map should yield empty result")
	}
}

// --- loadFullBlockState ------------------------------------------------

func writeBlockedIPsFile(t *testing.T, statePath string, ips []map[string]any) {
	t.Helper()
	if err := os.MkdirAll(statePath, 0755); err != nil {
		t.Fatal(err)
	}
	wrapper := map[string]any{"ips": ips}
	data, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statePath, "blocked_ips.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFullBlockStateMissingIsEmpty(t *testing.T) {
	// No state files; globals are unset in tests. loadFullBlockState
	// should return an empty map without panicking.
	got := loadFullBlockState(t.TempDir())
	if got == nil {
		t.Fatal("loadFullBlockState returned nil (want empty map)")
	}
	if len(got) != 0 {
		t.Errorf("empty state should yield empty map, got %+v", got)
	}
}

func TestLoadFullBlockStatePermanent(t *testing.T) {
	state := t.TempDir()
	ips := []map[string]any{
		{
			"ip":         "1.2.3.4",
			"reason":     "manual block",
			"blocked_at": time.Date(2026, 4, 11, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
			"expires_at": time.Time{}.Format(time.RFC3339Nano),
		},
	}
	writeBlockedIPsFile(t, state, ips)

	got := loadFullBlockState(state)
	entry, ok := got["1.2.3.4"]
	if !ok {
		t.Fatal("expected 1.2.3.4 in block map")
	}
	if !entry.permanent {
		t.Error("zero expires_at should mark as permanent")
	}
	if entry.reason != "manual block" {
		t.Errorf("reason = %q", entry.reason)
	}
}

func TestLoadFullBlockStateTemporary(t *testing.T) {
	state := t.TempDir()
	future := time.Now().Add(24 * time.Hour)
	ips := []map[string]any{
		{
			"ip":         "5.6.7.8",
			"reason":     "rate limit",
			"blocked_at": time.Now().Format(time.RFC3339Nano),
			"expires_at": future.Format(time.RFC3339Nano),
		},
	}
	writeBlockedIPsFile(t, state, ips)
	got := loadFullBlockState(state)
	entry, ok := got["5.6.7.8"]
	if !ok {
		t.Fatal("expected 5.6.7.8 in block map")
	}
	if entry.permanent {
		t.Error("future expiry should not be marked permanent")
	}
}

func TestLoadFullBlockStateExpiredSkipped(t *testing.T) {
	state := t.TempDir()
	past := time.Now().Add(-1 * time.Hour)
	ips := []map[string]any{
		{
			"ip":         "8.8.8.8",
			"reason":     "old block",
			"blocked_at": time.Now().Add(-2 * time.Hour).Format(time.RFC3339Nano),
			"expires_at": past.Format(time.RFC3339Nano),
		},
	}
	writeBlockedIPsFile(t, state, ips)
	got := loadFullBlockState(state)
	if _, ok := got["8.8.8.8"]; ok {
		t.Error("expired entry should be skipped")
	}
}

func TestLoadFullBlockStateMalformedJSON(t *testing.T) {
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "blocked_ips.json"), []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	got := loadFullBlockState(state)
	if len(got) != 0 {
		t.Errorf("malformed JSON should yield empty, got %+v", got)
	}
}

// --- Lookup / LookupBatch end-to-end -----------------------------------

func TestLookupWithClearGlobalsReturnsCleanVerdict(t *testing.T) {
	// No globals set, no state files → Lookup returns a clean verdict.
	state := t.TempDir()
	intel := Lookup("203.0.113.10", state)
	if intel == nil {
		t.Fatal("Lookup returned nil")
	}
	if intel.IP != "203.0.113.10" {
		t.Errorf("IP = %q", intel.IP)
	}
	if intel.Verdict != "clean" {
		t.Errorf("Verdict = %q, want clean", intel.Verdict)
	}
	if intel.AbuseScore != -1 {
		t.Errorf("AbuseScore = %d, want -1 (not cached)", intel.AbuseScore)
	}
	if intel.CurrentlyBlocked {
		t.Error("no state should not mark IP as blocked")
	}
}

func TestLookupAppliesAbuseCacheFromFile(t *testing.T) {
	state := t.TempDir()
	writeAbuseCacheFile(t, state, map[string]map[string]any{
		"203.0.113.11": {
			"score":      85,
			"category":   "brute",
			"checked_at": time.Now().Format(time.RFC3339Nano),
		},
	})

	intel := Lookup("203.0.113.11", state)
	if intel.AbuseScore != 85 {
		t.Errorf("AbuseScore = %d, want 85", intel.AbuseScore)
	}
	if intel.AbuseCategory != "brute" {
		t.Errorf("AbuseCategory = %q", intel.AbuseCategory)
	}
	if intel.Verdict != "malicious" {
		t.Errorf("Verdict = %q, want malicious", intel.Verdict)
	}
	if intel.UnifiedScore != 85 {
		t.Errorf("UnifiedScore = %d, want 85", intel.UnifiedScore)
	}
}

func TestLookupAppliesFlatFileBlockState(t *testing.T) {
	state := t.TempDir()
	writeBlockedIPsFile(t, state, []map[string]any{
		{
			"ip":         "203.0.113.12",
			"reason":     "fw rule",
			"blocked_at": time.Now().Format(time.RFC3339Nano),
			"expires_at": time.Time{}.Format(time.RFC3339Nano),
		},
	})

	intel := Lookup("203.0.113.12", state)
	if !intel.CurrentlyBlocked {
		t.Error("expected blocked")
	}
	if intel.Verdict != "blocked" {
		t.Errorf("Verdict = %q, want blocked", intel.Verdict)
	}
	if !intel.BlockPermanent {
		t.Error("zero expires_at should be marked permanent")
	}
}

func TestLookupBatchEmpty(t *testing.T) {
	state := t.TempDir()
	results := LookupBatch(nil, state)
	if results == nil {
		t.Fatal("LookupBatch returned nil slice for nil input")
	}
	if len(results) != 0 {
		t.Errorf("got %d results, want 0", len(results))
	}
}

func TestLookupBatchMixed(t *testing.T) {
	state := t.TempDir()
	writeAbuseCacheFile(t, state, map[string]map[string]any{
		"1.1.1.1": {"score": 85, "category": "abuse", "checked_at": time.Now().Format(time.RFC3339Nano)},
	})
	writeBlockedIPsFile(t, state, []map[string]any{
		{"ip": "2.2.2.2", "reason": "blocked", "blocked_at": time.Now().Format(time.RFC3339Nano), "expires_at": time.Time{}.Format(time.RFC3339Nano)},
	})

	results := LookupBatch([]string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, state)
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if results[0].Verdict != "malicious" {
		t.Errorf("results[0].Verdict = %q, want malicious", results[0].Verdict)
	}
	if results[1].Verdict != "blocked" {
		t.Errorf("results[1].Verdict = %q, want blocked", results[1].Verdict)
	}
	if results[2].Verdict != "clean" {
		t.Errorf("results[2].Verdict = %q, want clean", results[2].Verdict)
	}
}
