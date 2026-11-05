package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func openClearTestStore(t *testing.T) *state.Store {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestStoreLatestForgetsClearedFindings(t *testing.T) {
	const path = "/home/example/public_html/shell.php"
	f := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "webshell found", FilePath: path}
	for _, tc := range []struct {
		name     string
		coverage *state.ScanCoverage
		kept     bool
	}{
		{"covered and absent", nil, false},
		{"path not examined", &state.ScanCoverage{PreservePaths: map[string]map[string]bool{f.Check: {path: true}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := openClearTestStore(t)
			StoreLatestScanFindingsWithCoverage(st, []string{f.Check}, []alert.Finding{f}, nil)
			st.Update([]alert.Finding{f})

			StoreLatestScanFindingsWithCoverage(st, []string{f.Check}, nil, tc.coverage)

			if _, ok := st.EntryForKey(f.Key()); ok != tc.kept {
				t.Fatalf("alert entry kept = %t, want %t", ok, tc.kept)
			}
		})
	}
}

// Coverage gaps flap between runs: a run that happens to complete is no proof
// the next one will, so the gap clears only after 24h unseen.
func TestStoreLatestKeepsSelfHealthEntry(t *testing.T) {
	st := openClearTestStore(t)
	gap := alert.Finding{Check: "yara_scan_incomplete", Severity: alert.Warning, Message: "YARA scan incomplete", DedupKey: "host"}
	purge := []string{"yara_deep", "yara_scan_incomplete"}
	StoreLatestScanFindingsWithCoverage(st, purge, []alert.Finding{gap}, nil)
	st.Update([]alert.Finding{gap})

	StoreLatestScanFindingsWithCoverage(st, purge, nil, nil)

	if _, ok := st.EntryForKey(gap.Key()); !ok {
		t.Fatal("complete run without the gap forgot its alert entry")
	}
}

// Reputation health warnings are re-emitted only once a day; the runs in
// between keep the row. Those runs keep the delivery receipt alive too.
func TestReputationReminderKeepsDeliveryReceipt(t *testing.T) {
	statePath := t.TempDir()
	st, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := &config.Config{}
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	health := SharedSendersStale
	withSharedSendersHealth(t, &health, nil)
	check := namedCheck{name: "ip_reputation", fn: func(ctx context.Context, cfg *config.Config, st *state.Store) []alert.Finding {
		return reputationHealthFindings(ctx, cfg, nil, st, now, false)
	}}
	run := func() []alert.Finding {
		findings, purge := runParallelWithContext(context.Background(), cfg, st, []namedCheck{check}, "critical", true)
		StoreLatestScanFindings(st, purge, findings)
		return findings
	}

	first := run()
	if _, ok := findingWithCheck(first, "shared_senders_stale"); !ok {
		t.Fatalf("setup: no warning in %+v", first)
	}
	eligible, finish := st.BeginDelivery(first)
	finish(eligible)
	if len(eligible) != 1 {
		t.Fatalf("setup: %d findings eligible for delivery, want 1", len(eligible))
	}

	// The receipt is a day and a minute old when the next throttled run keeps
	// the row.
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(statePath, "state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]map[string]any{}
	if err = json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	entries[first[0].Key()]["last_seen"] = time.Now().Add(-24*time.Hour - time.Minute)
	if data, err = json.Marshal(entries); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err = state.Open(statePath); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if got := run(); len(got) != 0 || !containsFindingCheck(st.LatestFindings(), "shared_senders_stale") {
		t.Fatalf("throttled run raised %+v or dropped the warning", got)
	}

	now = now.Add(24 * time.Hour)
	reminder := run()
	if _, ok := findingWithCheck(reminder, "shared_senders_stale"); !ok {
		t.Fatal("setup: no daily reminder")
	}
	eligible, finish = st.BeginDelivery(reminder)
	finish(nil)
	if len(eligible) != 0 {
		t.Fatalf("daily reminder offered for delivery again: %+v", eligible)
	}
}
