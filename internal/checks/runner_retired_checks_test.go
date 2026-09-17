package checks

import (
	"context"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// retiredCheckNames are check names no longer emitted by any production
// code path but still present in the findings store of hosts upgrading
// from an older CSM.
//
// A finding is only ever cleared when its check name appears in the
// owning runner's purge list. Dropping a retired name from that list
// leaves every stored finding of that kind stuck in the active view
// forever, because nothing re-emits it and nothing purges it.
var retiredCheckNames = map[string]string{
	// Removed once modsec_disabled_vhost replaced it; the old
	// implementation misparsed disabled rules as disabled domains.
	"waf_bypass": "waf_status",
	// Emitted by the file index until a20c6f76 (content-first for
	// wp-content/languages and upgrade replaced them with
	// new_php_in_sensitive_dir).
	"new_php_in_languages": "file_index",
	"new_php_in_upgrade":   "file_index",
}

func TestRetiredCheckNamesStayPurgeable(t *testing.T) {
	for name, runner := range retiredCheckNames {
		purged := false
		for _, candidate := range runnerFindingNames[runner] {
			if candidate == name {
				purged = true
				break
			}
		}
		if !purged {
			t.Errorf("retired check %q is not in runnerFindingNames[%q], so findings written by older versions can never be cleared", name, runner)
		}
	}
}

func retiredFileIndexRows() []alert.Finding {
	return []alert.Finding{
		{Check: "new_php_in_languages", Severity: alert.Critical, Message: "PHP file in languages dir", FilePath: "/home/alice/public_html/wp-content/languages/x.php"},
		{Check: "new_php_in_upgrade", Severity: alert.Critical, Message: "PHP file in upgrade dir", FilePath: "/home/bob/public_html/wp-content/upgrade/y.php"},
	}
}

func fileIndexPurgeNames() []string {
	return append([]string(nil), runnerFindingNames["file_index"]...)
}

// Findings written by releases that still emitted the two retired file-index
// names are cleared by the next completed file_index scan and only then.
func TestRetiredFileIndexNamesPurgeOnCompleteScan(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	unrelated := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "shell", FilePath: "/home/carol/public_html/s.php"}
	st.SetLatestFindings(append(retiredFileIndexRows(), unrelated))

	fresh := alert.Finding{Check: "new_php_in_sensitive_dir", Severity: alert.Critical, Message: "fresh", FilePath: "/home/alice/public_html/wp-content/languages/z.php"}
	StoreLatestScanFindings(st, fileIndexPurgeNames(), []alert.Finding{fresh})

	got := st.LatestFindings()
	for _, name := range []string{"new_php_in_languages", "new_php_in_upgrade"} {
		if containsFindingCheck(got, name) {
			t.Errorf("retired %s survived a completed file_index scan: %+v", name, got)
		}
	}
	for _, name := range []string{"webshell", "new_php_in_sensitive_dir"} {
		if !containsFindingCheck(got, name) {
			t.Errorf("%s missing after merge: %+v", name, got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("active set = %d rows, want 2: %+v", len(got), got)
	}
}

func TestRetiredFileIndexNamesSurviveIncompleteOwner(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	st.SetLatestFindings(retiredFileIndexRows())

	check := namedCheck{name: "file_index", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		markCheckIncomplete(ctx, "file_index")
		return []alert.Finding{{Check: "new_suspicious_php", Severity: alert.High, Message: "partial", FilePath: "/home/carol/public_html/p.php"}}
	}}
	findings, purge := runParallelWithContext(context.Background(), &config.Config{}, st, []namedCheck{check}, "deep", true)
	for _, name := range []string{"new_php_in_languages", "new_php_in_upgrade"} {
		if slices.Contains(purge, name) {
			t.Errorf("incomplete file_index run purges %s: %v", name, purge)
		}
	}
	StoreLatestScanFindings(st, purge, findings)
	got := st.LatestFindings()
	for _, name := range []string{"new_php_in_languages", "new_php_in_upgrade", "new_suspicious_php"} {
		if !containsFindingCheck(got, name) {
			t.Errorf("%s missing after incomplete merge: %+v", name, got)
		}
	}
}

func TestRetiredFileIndexNamesInCompletedOwnerExpansion(t *testing.T) {
	names := latestPurgeCheckNamesForChecks([]namedCheck{{name: "file_index"}})
	for _, want := range []string{"new_php_in_languages", "new_php_in_upgrade"} {
		if !slices.Contains(names, want) {
			t.Errorf("completed file_index expansion lacks %s: %v", want, names)
		}
	}
	// obfuscated_php is shared with php_content and must keep its
	// all-owners-ran rule: file_index alone does not purge it.
	if slices.Contains(names, "obfuscated_php") {
		t.Errorf("shared name purged by a single owner: %v", names)
	}
}

func TestRetiredFileIndexNamesHonourCoverageGaps(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	st.SetLatestFindings(retiredFileIndexRows())

	gaps := map[string]map[string]bool{
		"new_php_in_upgrade": {"/home/bob/public_html/wp-content/upgrade/y.php": true},
	}
	StoreLatestScanFindingsWithGaps(st, fileIndexPurgeNames(), nil, gaps)
	got := st.LatestFindings()
	if containsFindingCheck(got, "new_php_in_languages") {
		t.Errorf("uncovered retired row survived: %+v", got)
	}
	if !containsFindingCheck(got, "new_php_in_upgrade") {
		t.Errorf("gap-protected retired row purged: %+v", got)
	}

	StoreLatestScanFindingsWithGaps(st, fileIndexPurgeNames(), nil, map[string]map[string]bool{})
	if got := st.LatestFindings(); containsFindingCheck(got, "new_php_in_upgrade") {
		t.Errorf("fully covered scan left the retired row: %+v", got)
	}
}
