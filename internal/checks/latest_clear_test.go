package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
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
