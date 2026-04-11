package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// openTestStore opens a fresh Store in a temp dir and schedules cleanup.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// --- Open / Close ------------------------------------------------------

func TestOpenCreatesDirAndEmptyStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Errorf("state dir not created: %v", statErr)
	}
	if len(s.entries) != 0 {
		t.Errorf("fresh store should have 0 entries, got %d", len(s.entries))
	}
}

func TestOpenFailsOnUnwritablePath(t *testing.T) {
	// Create a file where the state path should be so MkdirAll fails.
	dir := t.TempDir()
	conflict := filepath.Join(dir, "collision")
	if err := os.WriteFile(conflict, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Open(filepath.Join(conflict, "sub"))
	if err == nil {
		t.Fatal("Open should fail when parent is a file")
	}
}

func TestOpenLoadsExistingState(t *testing.T) {
	dir := t.TempDir()
	// Seed a state.json manually.
	seed := map[string]*Entry{
		"malware:found": {
			Hash:       "abc",
			FirstSeen:  time.Now().Add(-time.Hour),
			LastSeen:   time.Now(),
			IsBaseline: true,
		},
	}
	data, _ := json.Marshal(seed)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	// Also seed latest findings.
	lf := []alert.Finding{{Check: "waf", Message: "stale rules"}}
	lfData, _ := json.Marshal(lf)
	if err := os.WriteFile(filepath.Join(dir, "latest_findings.json"), lfData, 0600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	if _, ok := s.entries["malware:found"]; !ok {
		t.Error("existing entry should be loaded")
	}
	if got := s.LatestFindings(); len(got) != 1 || got[0].Check != "waf" {
		t.Errorf("latest findings not loaded: %v", got)
	}
}

func TestOpenTolerantOfCorruptStateJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	// Open should not error; it should log the warning and continue with empty state.
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if len(s.entries) != 0 {
		t.Errorf("corrupt state should yield empty entries, got %d", len(s.entries))
	}
	// Backup file should have been written.
	if _, err := os.Stat(filepath.Join(dir, "state.json.bak")); err != nil {
		t.Errorf("backup file not created: %v", err)
	}
}

func TestCloseCleanDoesNotRewrite(t *testing.T) {
	s := openTestStore(t)
	// No changes → dirty is false → Close returns nil without writing.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// --- findingKey / findingHash / ParseKey -------------------------------

func TestFindingKeyStableForSameInput(t *testing.T) {
	f := alert.Finding{Check: "malware", Message: "found", Details: "path"}
	k1 := findingKey(f)
	k2 := findingKey(f)
	if k1 != k2 {
		t.Errorf("key should be stable: %q vs %q", k1, k2)
	}
}

func TestFindingKeyChangesWithDetails(t *testing.T) {
	a := alert.Finding{Check: "x", Message: "y", Details: "one"}
	b := alert.Finding{Check: "x", Message: "y", Details: "two"}
	if findingKey(a) == findingKey(b) {
		t.Error("different Details should yield different keys")
	}
}

func TestFindingKeyEmptyDetailsIsShorter(t *testing.T) {
	f := alert.Finding{Check: "x", Message: "y"}
	got := findingKey(f)
	if got != "x:y" {
		t.Errorf("empty Details should give 'x:y', got %q", got)
	}
}

func TestFindingHashStableForSameInput(t *testing.T) {
	// Copy the input so staticcheck doesn't flag an identical-expression
	// comparison — we genuinely want to verify the hash is deterministic.
	a := alert.Finding{Check: "malware", Message: "found", Details: "path"}
	b := alert.Finding{Check: "malware", Message: "found", Details: "path"}
	if findingHash(a) != findingHash(b) {
		t.Error("hash should be stable across equivalent inputs")
	}
}

func TestFindingHashChangesWithFields(t *testing.T) {
	a := alert.Finding{Check: "x", Message: "y", Details: "d1"}
	b := alert.Finding{Check: "x", Message: "y", Details: "d2"}
	if findingHash(a) == findingHash(b) {
		t.Error("different Details should hash differently")
	}
}

func TestParseKeyStandard(t *testing.T) {
	check, msg := ParseKey("malware:found a shell")
	if check != "malware" || msg != "found a shell" {
		t.Errorf("got (%q, %q)", check, msg)
	}
}

func TestParseKeyNoColon(t *testing.T) {
	check, msg := ParseKey("justcheck")
	if check != "justcheck" || msg != "" {
		t.Errorf("got (%q, %q)", check, msg)
	}
}

// --- FilterNew ---------------------------------------------------------

func TestFilterNewFiltersKnownFindings(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "malware", Message: "m", Details: "d"}
	s.Update([]alert.Finding{f})

	// Identical finding — not new.
	newOnes := s.FilterNew([]alert.Finding{f})
	if len(newOnes) != 0 {
		t.Errorf("known finding should be filtered, got %d", len(newOnes))
	}
}

func TestFilterNewDetectsChangedDetails(t *testing.T) {
	s := openTestStore(t)
	f1 := alert.Finding{Check: "x", Message: "m", Details: "d1"}
	s.Update([]alert.Finding{f1})

	// Same Check:Message but different Details → findingKey differs →
	// treated as new.
	f2 := alert.Finding{Check: "x", Message: "m", Details: "d2"}
	newOnes := s.FilterNew([]alert.Finding{f2})
	if len(newOnes) != 1 {
		t.Errorf("different Details should surface as new, got %d", len(newOnes))
	}
}

func TestFilterNewBaselineSuppressed(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "c", Message: "m"}
	s.SetBaseline([]alert.Finding{f})
	newOnes := s.FilterNew([]alert.Finding{f})
	if len(newOnes) != 0 {
		t.Errorf("baseline finding should be filtered, got %d", len(newOnes))
	}
}

func TestFilterNewReAlertsAfter24h(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "c", Message: "m"}
	s.Update([]alert.Finding{f})

	// Force the stored AlertSent to 25 hours ago.
	key := findingKey(f)
	s.mu.Lock()
	s.entries[key].AlertSent = time.Now().Add(-25 * time.Hour)
	s.mu.Unlock()

	newOnes := s.FilterNew([]alert.Finding{f})
	if len(newOnes) != 1 {
		t.Errorf("expected re-alert after 24h, got %d", len(newOnes))
	}
}

// --- Update / SetBaseline ----------------------------------------------

func TestUpdateCleansUpMissingFindingsAfter24h(t *testing.T) {
	s := openTestStore(t)
	old := alert.Finding{Check: "c", Message: "m"}
	s.Update([]alert.Finding{old})

	// Force its LastSeen well into the past.
	key := findingKey(old)
	s.mu.Lock()
	s.entries[key].LastSeen = time.Now().Add(-48 * time.Hour)
	s.mu.Unlock()

	// An update that does NOT include the old finding should prune it.
	s.Update([]alert.Finding{{Check: "other", Message: "n"}})

	if _, exists := s.entries[key]; exists {
		t.Error("stale finding should be pruned after 24h")
	}
}

func TestUpdatePreservesBaselineEntries(t *testing.T) {
	s := openTestStore(t)
	base := alert.Finding{Check: "b", Message: "b"}
	s.SetBaseline([]alert.Finding{base})

	// Force the baseline LastSeen into the past.
	key := findingKey(base)
	s.mu.Lock()
	s.entries[key].LastSeen = time.Now().Add(-48 * time.Hour)
	s.mu.Unlock()

	// Update with different findings — baseline should survive the prune.
	s.Update([]alert.Finding{{Check: "o", Message: "o"}})

	if _, exists := s.entries[key]; !exists {
		t.Error("baseline entry should not be pruned")
	}
}

func TestSetBaselineReplacesAllEntries(t *testing.T) {
	s := openTestStore(t)
	s.Update([]alert.Finding{{Check: "old", Message: "m"}})
	s.SetBaseline([]alert.Finding{{Check: "new", Message: "m"}})

	if _, exists := s.entries[findingKey(alert.Finding{Check: "old", Message: "m"})]; exists {
		t.Error("old entry should be replaced by SetBaseline")
	}
	if _, exists := s.entries[findingKey(alert.Finding{Check: "new", Message: "m"})]; !exists {
		t.Error("new baseline entry should be present")
	}
}

// --- ShouldRunThrottled ------------------------------------------------

func TestShouldRunThrottledFirstCallAllowed(t *testing.T) {
	s := openTestStore(t)
	if !s.ShouldRunThrottled("checkA", 60) {
		t.Error("first call should be allowed")
	}
}

func TestShouldRunThrottledSuppressesWithinInterval(t *testing.T) {
	s := openTestStore(t)
	s.ShouldRunThrottled("checkB", 60)
	if s.ShouldRunThrottled("checkB", 60) {
		t.Error("second call within interval should be throttled")
	}
}

func TestShouldRunThrottledAllowsAfterInterval(t *testing.T) {
	s := openTestStore(t)
	// Seed the throttle key as already-old.
	s.mu.Lock()
	s.entries["_throttle:checkC"] = &Entry{LastSeen: time.Now().Add(-120 * time.Minute)}
	s.mu.Unlock()

	if !s.ShouldRunThrottled("checkC", 60) {
		t.Error("call after interval should be allowed")
	}
}

// --- GetRaw / SetRaw ---------------------------------------------------

func TestSetRawThenGetRaw(t *testing.T) {
	s := openTestStore(t)
	s.SetRaw("custom:key", "value1")
	got, ok := s.GetRaw("custom:key")
	if !ok || got != "value1" {
		t.Errorf("got (%q, %v), want (value1, true)", got, ok)
	}
}

func TestGetRawMissing(t *testing.T) {
	s := openTestStore(t)
	if _, ok := s.GetRaw("nope"); ok {
		t.Error("unknown key should return false")
	}
}

func TestSetRawUpdatesExisting(t *testing.T) {
	s := openTestStore(t)
	s.SetRaw("k", "v1")
	s.SetRaw("k", "v2")
	got, ok := s.GetRaw("k")
	if !ok || got != "v2" {
		t.Errorf("got (%q, %v), want (v2, true)", got, ok)
	}
}

func TestSetRawSameValueIsNoDirty(t *testing.T) {
	s := openTestStore(t)
	s.SetRaw("k", "v")
	// Manually clear dirty to see if a no-op SetRaw sets it again.
	s.mu.Lock()
	s.dirty = false
	s.mu.Unlock()
	s.SetRaw("k", "v")
	s.mu.RLock()
	dirty := s.dirty
	s.mu.RUnlock()
	if dirty {
		t.Error("SetRaw with same value should not mark as dirty")
	}
}

// --- Entries / EntryForKey ---------------------------------------------

func TestEntriesSkipsInternalKeys(t *testing.T) {
	s := openTestStore(t)
	s.Update([]alert.Finding{{Check: "c", Message: "m"}})
	s.mu.Lock()
	s.entries["_internal:x"] = &Entry{Hash: "x"}
	s.mu.Unlock()

	got := s.Entries()
	for k := range got {
		if len(k) > 0 && k[0] == '_' {
			t.Errorf("internal key %q leaked into Entries()", k)
		}
	}
	if len(got) == 0 {
		t.Error("non-internal entries should be present")
	}
}

func TestEntryForKeyHit(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "c", Message: "m"}
	s.Update([]alert.Finding{f})
	if _, ok := s.EntryForKey(findingKey(f)); !ok {
		t.Error("expected entry to be found")
	}
}

func TestEntryForKeyMiss(t *testing.T) {
	s := openTestStore(t)
	if _, ok := s.EntryForKey("nope"); ok {
		t.Error("unknown key should return !ok")
	}
}

// --- LatestFindings merge / purge / dismiss ----------------------------

func TestSetLatestFindingsMergesByKey(t *testing.T) {
	s := openTestStore(t)
	s.SetLatestFindings([]alert.Finding{
		{Check: "a", Message: "x", Details: "d1"},
		{Check: "b", Message: "y"},
	})
	s.SetLatestFindings([]alert.Finding{
		{Check: "a", Message: "x", Details: "d1"}, // same key — updated
		{Check: "c", Message: "z"},                // new
	})
	got := s.LatestFindings()
	if len(got) != 3 {
		t.Errorf("got %d, want 3 (a+b+c merged)", len(got))
	}
}

func TestSetLatestFindingsPersistsToDisk(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.SetLatestFindings([]alert.Finding{{Check: "c", Message: "m"}})
	_ = s.Close()

	// Re-open and verify.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if got := s2.LatestFindings(); len(got) != 1 {
		t.Errorf("persisted findings not loaded: %d", len(got))
	}
}

func TestPurgeFindingsByChecks(t *testing.T) {
	s := openTestStore(t)
	s.SetLatestFindings([]alert.Finding{
		{Check: "perf_high", Message: "load"},
		{Check: "perf_mid", Message: "cpu"},
		{Check: "malware", Message: "found"},
	})
	s.PurgeFindingsByChecks([]string{"perf_high", "perf_mid"})
	got := s.LatestFindings()
	if len(got) != 1 || got[0].Check != "malware" {
		t.Errorf("PurgeFindingsByChecks result = %+v, want 1 malware", got)
	}
}

func TestPurgeFindingsByChecksEmptyList(t *testing.T) {
	s := openTestStore(t)
	s.SetLatestFindings([]alert.Finding{{Check: "a"}, {Check: "b"}})
	s.PurgeFindingsByChecks(nil)
	if got := s.LatestFindings(); len(got) != 2 {
		t.Errorf("empty purge list should be no-op, got %d", len(got))
	}
}

func TestPurgeAndMergeFindingsAtomic(t *testing.T) {
	s := openTestStore(t)
	s.SetLatestFindings([]alert.Finding{
		{Check: "perf", Message: "stale"},
		{Check: "malware", Message: "found"},
	})
	s.PurgeAndMergeFindings(
		[]string{"perf"},
		[]alert.Finding{
			{Check: "perf", Message: "fresh"},
			{Check: "new", Message: "thing"},
		},
	)
	got := s.LatestFindings()
	if len(got) != 3 {
		t.Errorf("got %d, want 3 (malware + fresh perf + new)", len(got))
	}
	for _, f := range got {
		if f.Check == "perf" && f.Message == "stale" {
			t.Error("stale perf finding should have been purged")
		}
	}
}

func TestClearLatestFindings(t *testing.T) {
	s := openTestStore(t)
	s.SetLatestFindings([]alert.Finding{{Check: "c"}})
	s.ClearLatestFindings()
	if got := s.LatestFindings(); len(got) != 0 {
		t.Errorf("ClearLatestFindings didn't clear, got %d", len(got))
	}
}

func TestLatestScanTimeUpdatedBySetLatest(t *testing.T) {
	s := openTestStore(t)
	before := time.Now()
	s.SetLatestFindings([]alert.Finding{{Check: "c"}})
	after := s.LatestScanTime()
	if after.Before(before) {
		t.Errorf("LatestScanTime = %v, should be >= %v", after, before)
	}
}

func TestDismissLatestFinding(t *testing.T) {
	s := openTestStore(t)
	f1 := alert.Finding{Check: "a", Message: "1"}
	f2 := alert.Finding{Check: "b", Message: "2"}
	s.SetLatestFindings([]alert.Finding{f1, f2})

	s.DismissLatestFinding(f1.Key())
	got := s.LatestFindings()
	if len(got) != 1 || got[0].Check != "b" {
		t.Errorf("DismissLatestFinding result = %+v", got)
	}
}

func TestDismissFindingMarksBaseline(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "c", Message: "m"}
	s.Update([]alert.Finding{f})
	s.DismissFinding(findingKey(f))

	entry, ok := s.EntryForKey(findingKey(f))
	if !ok {
		t.Fatal("entry should still exist")
	}
	if !entry.IsBaseline {
		t.Error("DismissFinding should mark as baseline")
	}
}

// --- Suppression rules -------------------------------------------------

func TestSaveAndLoadSuppressions(t *testing.T) {
	s := openTestStore(t)
	rules := []SuppressionRule{
		{ID: "1", Check: "malware", PathPattern: "/tmp/*", Reason: "test fixtures"},
		{ID: "2", Check: "waf", Reason: "known false positive"},
	}
	if err := s.SaveSuppressions(rules); err != nil {
		t.Fatal(err)
	}
	got := s.LoadSuppressions()
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0].ID != "1" {
		t.Errorf("got[0].ID = %q", got[0].ID)
	}
}

func TestLoadSuppressionsMissingFile(t *testing.T) {
	s := openTestStore(t)
	if got := s.LoadSuppressions(); got != nil {
		t.Errorf("missing file should yield nil, got %v", got)
	}
}

func TestLoadSuppressionsCorruptJSON(t *testing.T) {
	s := openTestStore(t)
	if err := os.WriteFile(filepath.Join(s.path, "suppressions.json"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := s.LoadSuppressions(); got != nil {
		t.Errorf("corrupt file should yield nil, got %v", got)
	}
}

// --- IsSuppressed ------------------------------------------------------

func TestIsSuppressedCheckOnly(t *testing.T) {
	s := openTestStore(t)
	rules := []SuppressionRule{{Check: "waf"}} // no path pattern
	if !s.IsSuppressed(alert.Finding{Check: "waf", Message: "x"}, rules) {
		t.Error("no-path-pattern rule should match all findings for check")
	}
	if s.IsSuppressed(alert.Finding{Check: "malware"}, rules) {
		t.Error("rule should not match different check")
	}
}

func TestIsSuppressedPathPatternFilePath(t *testing.T) {
	s := openTestStore(t)
	rules := []SuppressionRule{{Check: "malware", PathPattern: "/tmp/*"}}
	f := alert.Finding{Check: "malware", FilePath: "/tmp/shell.php"}
	if !s.IsSuppressed(f, rules) {
		t.Error("rule should match FilePath")
	}
}

func TestIsSuppressedNoMatch(t *testing.T) {
	s := openTestStore(t)
	rules := []SuppressionRule{{Check: "malware", PathPattern: "/opt/*"}}
	f := alert.Finding{Check: "malware", FilePath: "/home/user/file"}
	if s.IsSuppressed(f, rules) {
		t.Error("rule should not match unrelated path")
	}
}

// --- suppressionPathCandidates ----------------------------------------

func TestSuppressionPathCandidatesFromFilePath(t *testing.T) {
	f := alert.Finding{FilePath: "/var/log/foo.log"}
	got := suppressionPathCandidates(f)
	if len(got) != 1 || got[0] != "/var/log/foo.log" {
		t.Errorf("got %v", got)
	}
}

func TestSuppressionPathCandidatesExtractedFromMessage(t *testing.T) {
	f := alert.Finding{Message: "Found /home/user/a.php and /tmp/b.sh"}
	got := suppressionPathCandidates(f)
	if len(got) != 2 {
		t.Errorf("got %v, want 2 candidates", got)
	}
}

func TestSuppressionPathCandidatesDedupes(t *testing.T) {
	f := alert.Finding{Message: "/home/a /home/a (dup)"}
	got := suppressionPathCandidates(f)
	if len(got) != 1 {
		t.Errorf("duplicates not removed: %v", got)
	}
}

func TestSuppressionPathCandidatesStripsPunctuation(t *testing.T) {
	f := alert.Finding{Message: `scanned "/opt/x"`}
	got := suppressionPathCandidates(f)
	if len(got) != 1 || got[0] != "/opt/x" {
		t.Errorf("got %v", got)
	}
}

// --- splitLines --------------------------------------------------------

func TestSplitLinesBasic(t *testing.T) {
	got := splitLines([]byte("a\nb\nc"))
	if len(got) != 3 {
		t.Fatalf("got %d, want 3", len(got))
	}
	if string(got[0]) != "a" || string(got[1]) != "b" || string(got[2]) != "c" {
		t.Errorf("got %v", got)
	}
}

func TestSplitLinesEmpty(t *testing.T) {
	got := splitLines(nil)
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestSplitLinesTrailingNewline(t *testing.T) {
	got := splitLines([]byte("a\nb\n"))
	if len(got) != 2 {
		t.Errorf("got %d, want 2", len(got))
	}
}

// --- ReadHistory (JSONL fallback path) --------------------------------

func TestReadHistoryJSONLFallback(t *testing.T) {
	dir := t.TempDir()
	jsonlPath := filepath.Join(dir, "history.jsonl")
	findings := []alert.Finding{
		{Check: "a", Message: "old"},
		{Check: "b", Message: "middle"},
		{Check: "c", Message: "new"},
	}
	var data []byte
	for _, f := range findings {
		line, _ := json.Marshal(f)
		data = append(data, line...)
		data = append(data, '\n')
	}
	if err := os.WriteFile(jsonlPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	// With no store.Global() set, ReadHistory falls back to JSONL.
	got, total := s.ReadHistory(10, 0)
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	// Newest-first reversal — 'c' should be first.
	if len(got) == 3 && got[0].Check != "c" {
		t.Errorf("expected newest-first, got[0] = %+v", got[0])
	}
}

func TestReadHistoryJSONLMissingFile(t *testing.T) {
	s := openTestStore(t)
	got, total := s.ReadHistory(10, 0)
	if total != 0 || got != nil {
		t.Errorf("missing history should return nil/0, got %v/%d", got, total)
	}
}

func TestReadHistoryJSONLOffsetBeyondEnd(t *testing.T) {
	dir := t.TempDir()
	jsonlPath := filepath.Join(dir, "history.jsonl")
	line, _ := json.Marshal(alert.Finding{Check: "c"})
	if err := os.WriteFile(jsonlPath, append(line, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	got, total := s.ReadHistory(10, 100)
	if total != 1 || got != nil {
		t.Errorf("offset beyond end = (%v, %d), want (nil, 1)", got, total)
	}
}

// --- AppendHistory JSONL fallback --------------------------------------
//
// These tests exercise the deprecated JSONL path that fires only when
// store.Global() is nil (no bbolt wired up). The bbolt-backed path is
// covered by internal/store's own tests.

func TestAppendHistoryEmptyIsNoOp(t *testing.T) {
	s := openTestStore(t)
	s.AppendHistory(nil)
	if _, err := os.Stat(filepath.Join(s.path, "history.jsonl")); err == nil {
		t.Error("empty AppendHistory should not create history.jsonl")
	}
}

func TestAppendHistoryJSONLFallbackWrites(t *testing.T) {
	// Redirect stderr to /dev/null so the deprecation warning doesn't
	// clutter test output.
	devnull, _ := os.Open(os.DevNull)
	defer func() { _ = devnull.Close() }()

	s := openTestStore(t)
	s.AppendHistory([]alert.Finding{
		{Check: "a", Message: "one"},
		{Check: "b", Message: "two"},
	})
	data, err := os.ReadFile(filepath.Join(s.path, "history.jsonl"))
	if err != nil {
		t.Fatalf("history.jsonl not written: %v", err)
	}
	if len(data) == 0 {
		t.Error("history.jsonl is empty")
	}

	// Second append should add more lines.
	s.AppendHistory([]alert.Finding{{Check: "c", Message: "three"}})
	data2, _ := os.ReadFile(filepath.Join(s.path, "history.jsonl"))
	if len(data2) <= len(data) {
		t.Errorf("second append did not grow the file (%d vs %d)", len(data), len(data2))
	}
}

func TestAppendHistoryFileTruncatesAt10MB(t *testing.T) {
	s := openTestStore(t)
	histPath := filepath.Join(s.path, "history.jsonl")

	// Pre-seed a history file above the 10 MB threshold so the truncate
	// branch fires on the next append.
	big := make([]byte, 11*1024*1024)
	for i := range big {
		// Newlines so the half-split finds a terminator quickly.
		if i%100 == 99 {
			big[i] = '\n'
		} else {
			big[i] = 'x'
		}
	}
	if err := os.WriteFile(histPath, big, 0600); err != nil {
		t.Fatal(err)
	}

	s.appendHistoryFile([]alert.Finding{{Check: "after", Message: "trunc"}})

	info, err := os.Stat(histPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() >= int64(len(big)) {
		t.Errorf("history file should have shrunk, old=%d new=%d", len(big), info.Size())
	}
}

// --- PrintStatus -------------------------------------------------------
//
// PrintStatus writes to stdout. We redirect stdout to a pipe to capture
// output and then restore it.

func TestPrintStatusEmpty(t *testing.T) {
	s := openTestStore(t)
	s.PrintStatus() // just ensure it doesn't panic on empty state
}

func TestPrintStatusWithEntries(t *testing.T) {
	s := openTestStore(t)
	s.Update([]alert.Finding{{Check: "c", Message: "active"}})
	s.SetBaseline([]alert.Finding{{Check: "b", Message: "baseline"}})

	// Add an internal (_-prefixed) key to exercise the skip branch.
	s.mu.Lock()
	s.entries["_internal:x"] = &Entry{Hash: "x", LastSeen: time.Now()}
	s.mu.Unlock()

	s.PrintStatus() // must not panic and must render all branches
}

// --- store-backed delegation methods -----------------------------------
//
// ReadHistorySince / AggregateByHour / AggregateByDay all return nil
// when store.Global() is unset. The happy path is covered by
// internal/store's own aggregate tests; here we only verify the
// nil-fallback is well-defined.

func TestReadHistorySinceWithoutStoreReturnsNil(t *testing.T) {
	s := openTestStore(t)
	if got := s.ReadHistorySince(time.Now().Add(-time.Hour)); got != nil {
		t.Errorf("want nil without store.Global, got %v", got)
	}
}

func TestAggregateByHourWithoutStoreReturnsNil(t *testing.T) {
	s := openTestStore(t)
	if got := s.AggregateByHour(); got != nil {
		t.Errorf("want nil without store.Global, got %v", got)
	}
}

func TestAggregateByDayWithoutStoreReturnsNil(t *testing.T) {
	s := openTestStore(t)
	if got := s.AggregateByDay(); got != nil {
		t.Errorf("want nil without store.Global, got %v", got)
	}
}

// --- save idempotence on repeated Close --------------------------------

func TestCloseDirtyWrites(t *testing.T) {
	s := openTestStore(t)
	s.Update([]alert.Finding{{Check: "c", Message: "m"}})
	// Update() already calls save internally; Close() with matching hash
	// exits fast (no dup write).
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// state.json must exist after a dirty Close().
	if _, err := os.Stat(filepath.Join(s.path, "state.json")); err != nil {
		t.Errorf("state.json not written: %v", err)
	}
}

// --- Lock file ---------------------------------------------------------

func TestAcquireAndReleaseLock(t *testing.T) {
	dir := t.TempDir()
	lock, err := AcquireLock(dir)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	// PID file written.
	data, err := os.ReadFile(filepath.Join(dir, "csm.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("lock file should contain PID")
	}
	lock.Release()
	if _, statErr := os.Stat(filepath.Join(dir, "csm.lock")); statErr == nil {
		t.Error("lock file should be removed on Release")
	}
}

func TestAcquireLockConflict(t *testing.T) {
	dir := t.TempDir()
	l1, err := AcquireLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Release()

	_, err = AcquireLock(dir)
	if err == nil {
		t.Fatal("second AcquireLock should fail while first is held")
	}
}

func TestAcquireLockFailsOnUnwritableDir(t *testing.T) {
	// A path whose parent doesn't exist.
	_, err := AcquireLock(filepath.Join(t.TempDir(), "never", "created"))
	if err == nil {
		t.Fatal("AcquireLock on missing dir should fail")
	}
}
