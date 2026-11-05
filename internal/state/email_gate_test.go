package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func gateKeys(findings []alert.Finding) []string {
	keys := make([]string, 0, len(findings))
	for _, f := range findings {
		keys = append(keys, f.Key())
	}
	return keys
}

func TestFilterUnemailedSkipsDeliveredContent(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "shell in upload", Details: "first"}
	s.Update([]alert.Finding{f})
	s.MarkEmailed([]alert.Finding{f})
	if got := s.FilterUnemailed([]alert.Finding{f}); len(got) != 0 {
		t.Fatalf("delivered content offered again: %v", gateKeys(got))
	}

	changed := f
	changed.Details = "second"
	if got := s.FilterUnemailed([]alert.Finding{changed}); len(got) != 1 || got[0].Key() != changed.Key() {
		t.Fatalf("changed content held back: %v", gateKeys(got))
	}

	// The same identity with a different delivered fingerprint is new content.
	s.mu.Lock()
	s.entries[f.Key()].Emailed = "older content"
	s.mu.Unlock()
	if got := s.FilterUnemailed([]alert.Finding{f}); len(got) != 1 {
		t.Fatalf("content delivered under an older fingerprint held back: %v", gateKeys(got))
	}
}

func TestFilterUnemailedKeepsUndelivered(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "shell in upload"}
	s.Update([]alert.Finding{f})
	if got := s.FilterUnemailed([]alert.Finding{f}); len(got) != 1 {
		t.Fatalf("alerted but undelivered finding held back: %v", gateKeys(got))
	}
}

func TestFilterUnemailedBaselineAndDismissal(t *testing.T) {
	baseline := alert.Finding{Check: "webshell", Message: "baseline"}
	dismissed := alert.Finding{Check: "webshell", Message: "dismissed"}

	s := openTestStore(t)
	s.SetBaseline([]alert.Finding{baseline})
	s.Update([]alert.Finding{dismissed})
	s.DismissFinding(dismissed.Key())

	if got := s.FilterUnemailed([]alert.Finding{baseline, dismissed}); len(got) != 0 {
		t.Fatalf("baseline or dismissed finding offered for email: %v", gateKeys(got))
	}
}

func TestFilterUnemailedRefreshesLastSeen(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "auto_block", Message: "AUTO-BLOCK: 203.0.113.7"}
	s.MarkEmailed([]alert.Finding{f})
	old := time.Now().Add(-20 * time.Hour)
	s.mu.Lock()
	s.entries[f.Key()].LastSeen = old
	s.dirty = false
	s.mu.Unlock()

	if got := s.FilterUnemailed([]alert.Finding{f}); len(got) != 0 {
		t.Fatalf("delivered finding offered again: %v", gateKeys(got))
	}
	entry, ok := s.EntryForKey(f.Key())
	if !ok || !entry.LastSeen.After(old) {
		t.Fatalf("dropped finding did not refresh LastSeen: %+v", entry)
	}
	s.mu.RLock()
	dirty := s.dirty
	s.mu.RUnlock()
	if !dirty {
		t.Fatal("LastSeen refresh left the state clean, so it would not persist")
	}
}

func TestMarkEmailedCreatesEntry(t *testing.T) {
	s := openTestStore(t)
	action := alert.Finding{Check: "auto_block", Severity: alert.High, Message: "AUTO-BLOCK: 203.0.113.9"}
	if got := s.FilterUnemailed([]alert.Finding{action}); len(got) != 1 {
		t.Fatalf("action with no entry held back: %v", gateKeys(got))
	}

	s.MarkEmailed([]alert.Finding{action})
	entry, ok := s.EntryForKey(action.Key())
	if !ok || entry.Hash != action.Fingerprint() || entry.Emailed != action.Fingerprint() ||
		entry.FirstSeen.IsZero() || entry.LastSeen.IsZero() || entry.AlertSent.IsZero() {
		t.Fatalf("MarkEmailed entry = %+v, ok=%t", entry, ok)
	}
	if got := s.FilterUnemailed([]alert.Finding{action}); len(got) != 0 {
		t.Fatalf("delivered action offered again: %v", gateKeys(got))
	}

	s.mu.Lock()
	s.entries[action.Key()].LastSeen = time.Now().Add(-25 * time.Hour)
	s.mu.Unlock()
	s.Update(nil)
	if got := s.FilterUnemailed([]alert.Finding{action}); len(got) != 1 {
		t.Fatalf("action unseen for 25h still held back: %v", gateKeys(got))
	}
}

func writeStateFile(t *testing.T, dir string, entries map[string]*Entry) {
	t.Helper()
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenMarksAlertedEntriesEmailed(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	a := alert.Finding{Check: "webshell", Message: "alerted before upgrade"}
	b := alert.Finding{Check: "webshell", Message: "never alerted"}
	baseline := alert.Finding{Check: "webshell", Message: "baseline"}
	writeStateFile(t, dir, map[string]*Entry{
		a.Key():         {Hash: a.Fingerprint(), FirstSeen: now, LastSeen: now, AlertSent: now},
		b.Key():         {Hash: b.Fingerprint(), FirstSeen: now, LastSeen: now},
		baseline.Key():  {Hash: baseline.Fingerprint(), FirstSeen: now, LastSeen: now, AlertSent: now, IsBaseline: true},
		"_throttle:any": {Hash: "raw", LastSeen: now, AlertSent: now},
	})

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := s.FilterUnemailed([]alert.Finding{a, b})
	if len(got) != 1 || got[0].Key() != b.Key() {
		t.Fatalf("after upgrade got %v, want only %s", gateKeys(got), b.Key())
	}
	if _, ok := s.GetRaw(emailGateMetaKey); !ok {
		t.Fatal("upgrade marker not set")
	}
	for _, key := range []string{baseline.Key(), "_throttle:any"} {
		if entry, _ := s.EntryForKey(key); entry.Emailed != "" {
			t.Errorf("%s migrated: %+v", key, entry)
		}
	}

	c := alert.Finding{Check: "webshell", Message: "alerted after upgrade"}
	s.Update([]alert.Finding{c})
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	got = reopened.FilterUnemailed([]alert.Finding{a, b, c})
	if len(got) != 2 || got[0].Key() != b.Key() || got[1].Key() != c.Key() {
		t.Fatalf("after reopening got %v, want %s and %s", gateKeys(got), b.Key(), c.Key())
	}
}

// A store that already records deliveries was written by a gated build. Only
// the marker is missing (a fresh install that has not restarted yet), so a
// finding the cap held back must keep its retry.
func TestOpenSkipsMigrationOfGatedState(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	delivered := alert.Finding{Check: "webshell", Message: "delivered"}
	capped := alert.Finding{Check: "webshell", Message: "held back by the cap"}
	writeStateFile(t, dir, map[string]*Entry{
		delivered.Key(): {Hash: delivered.Fingerprint(), FirstSeen: now, LastSeen: now, AlertSent: now, Emailed: delivered.Fingerprint()},
		capped.Key():    {Hash: capped.Fingerprint(), FirstSeen: now, LastSeen: now, AlertSent: now},
	})
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	got := s.FilterUnemailed([]alert.Finding{delivered, capped})
	if len(got) != 1 || got[0].Key() != capped.Key() {
		t.Fatalf("got %v, want only %s", gateKeys(got), capped.Key())
	}
	if _, ok := s.GetRaw(emailGateMetaKey); !ok {
		t.Fatal("marker not set")
	}
}

func retiredKeys(retired []alert.Finding) map[string]bool {
	keys := make(map[string]bool, len(retired))
	for _, f := range retired {
		keys[f.Key()] = true
	}
	return keys
}

func TestPurgeAndMergeReturnsRetired(t *testing.T) {
	const gapPath = "/home/example/public_html/gap.php"
	cleared := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "cleared", FilePath: "/home/example/public_html/a.php"}
	gap := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "unexamined", FilePath: gapPath}
	demoted := alert.Finding{Check: "webshell", Severity: alert.Warning, DemotedFrom: alert.High, Message: "demoted"}
	reported := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "reported again"}
	other := alert.Finding{Check: "other_check", Severity: alert.Critical, Message: "not purged"}
	scoped := alert.Finding{Check: "db_scan", Severity: alert.High, Message: "scope done", CoverageScope: "db1"}
	derivedGone := alert.Finding{Check: "derived_check", Severity: alert.High, Message: "no longer derived"}
	derivedKept := alert.Finding{Check: "derived_check", Severity: alert.High, Message: "derived again"}
	// Purged by the first pass and derived again by the second.
	crossPass := alert.Finding{Check: "derived_purged", Severity: alert.High, Message: "both passes"}

	s := openTestStore(t)
	s.SetLatestFindings([]alert.Finding{cleared, gap, demoted, reported, other, scoped, derivedGone, derivedKept, crossPass})
	retired := s.PurgeAndMergeFindingsDerivedWithCoverage(
		[]string{"webshell", "derived_purged"},
		[]alert.Finding{reported},
		&ScanCoverage{
			PreservePaths:   map[string]map[string]bool{"webshell": {gapPath: true}},
			CompletedScopes: map[string]map[string]bool{"db_scan": {"db1": true}},
		},
		[]string{"derived_check", "derived_purged"},
		func([]alert.Finding) []alert.Finding { return []alert.Finding{derivedKept, crossPass} },
	)
	got := retiredKeys(retired)
	want := map[string]bool{cleared.Key(): true, scoped.Key(): true, derivedGone.Key(): true}
	if len(got) != len(want) || len(retired) != len(want) {
		t.Fatalf("retired = %v, want %v", got, want)
	}
	for key := range want {
		if !got[key] {
			t.Fatalf("retired = %v, missing %s", got, key)
		}
	}

	// A row the cap evicts was not cleared by any scan.
	evicted := alert.Finding{Check: "other_check", Severity: alert.Warning, Message: "evicted", Timestamp: time.Unix(1, 0)}
	capped := openTestStore(t)
	capped.SetLatestFindings([]alert.Finding{evicted})
	flood := make([]alert.Finding, latestFindingsCap)
	for i := range flood {
		flood[i] = alert.Finding{Check: "flood", Severity: alert.High, Message: fmt.Sprintf("row %d", i), Timestamp: time.Unix(1000, 0)}
	}
	retired = capped.PurgeAndMergeFindingsDerivedWithCoverage([]string{"flood"}, flood, nil, nil, nil)
	if len(retired) != 0 {
		t.Fatalf("cap eviction reported as retired: %v", gateKeys(retired))
	}
	for _, f := range capped.LatestFindings() {
		if f.Key() == evicted.Key() {
			t.Fatal("setup: the cap did not evict the low-priority row")
		}
	}
}

func TestForgetClearedKeepsBaseline(t *testing.T) {
	s := openTestStore(t)
	baseline := alert.Finding{Check: "webshell", Message: "baseline"}
	active := alert.Finding{Check: "webshell", Message: "active"}
	internal := alert.Finding{Check: "_throttle", Message: "probe"}
	s.SetBaseline([]alert.Finding{baseline})
	s.Update([]alert.Finding{active})
	s.MarkEmailed([]alert.Finding{active})
	s.SetRaw(internal.Key(), "raw")

	s.ForgetCleared([]alert.Finding{baseline, active, internal})

	if _, ok := s.EntryForKey(active.Key()); ok {
		t.Fatal("cleared entry kept")
	}
	if entry, ok := s.EntryForKey(baseline.Key()); !ok || !entry.IsBaseline {
		t.Fatalf("baseline entry forgotten: %+v ok=%t", entry, ok)
	}
	if _, ok := s.GetRaw(internal.Key()); !ok {
		t.Fatal("internal entry forgotten")
	}
	if got := s.FilterUnemailed([]alert.Finding{active}); len(got) != 1 {
		t.Fatalf("cleared finding held back on return: %v", gateKeys(got))
	}
}
