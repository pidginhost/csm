package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A dismissed finding is accepted by the operator, so it must not keep raising
// a cross-account aggregate. Bob's webshell is the source both aggregates need:
// without it two accounts have critical events and one has the webshell.
func dismissalCorrelationBatch() []alert.Finding {
	return []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", FilePath: "/home/alice/public_html/a.php", Message: "alice"},
		{Severity: alert.Critical, Check: "webshell", FilePath: "/home/bob/public_html/b.php", Message: "bob"},
		{Severity: alert.Critical, Check: "db_rogue_admin", FilePath: "/home/carol/public_html/wp-config.php", Message: "carol"},
	}
}

func runDismissalScan(st *state.Store, batch []alert.Finding) []alert.Finding {
	rows, _ := runParallel(&config.Config{}, st, []namedCheck{{name: "webshell", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		return batch
	}}}, "test", true)
	return rows
}

func requireChangedContentAggregates(t *testing.T, st *state.Store, batch []alert.Finding) {
	t.Helper()
	scan := runDismissalScan(st, batch)
	StoreLatestScanFindings(st, []string{"webshell", "db_rogue_admin"}, scan)
	for path, rows := range map[string][]alert.Finding{"scan": scan, "stored": st.LatestFindings()} {
		counts := checksIn(rows)
		if counts["coordinated_attack"] != 1 || counts["cross_account_malware"] != 1 {
			t.Errorf("%s counts = %v, want both aggregates for changed content", path, counts)
		}
	}
}

func TestScanCountsDismissedAttributionGaps(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	st := newTestStore(t)
	f := alert.Finding{Severity: alert.Critical, Check: "webshell", Message: "owner unknown"}
	st.SetBaseline([]alert.Finding{f})
	before := AttributionHealth().Cumulative[f.Check]
	rows := runDismissalScan(st, []alert.Finding{f})
	if len(rows) != 1 || rows[0].Key() != f.Key() {
		t.Fatalf("scan rows = %v, want the original finding", rows)
	}
	if got := AttributionHealth().Cumulative[f.Check] - before; got != 1 {
		t.Errorf("scan recorded %d attribution gaps, want 1", got)
	}
}

func TestCorrelationRecognizesChangedDismissedContent(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	st := newTestStore(t)
	batch := dismissalCorrelationBatch()
	source := &batch[1]
	source.ContentSHA256 = strings.Repeat("a", 64)
	st.SetLatestFindings(batch)
	_, ok := st.DismissFindingAsShown(source.Key(), source.ContentSHA256)
	if !ok {
		t.Fatal("could not dismiss the listed content")
	}
	source.ContentSHA256 = strings.Repeat("b", 64)
	source.ScanCarryForward = true
	if got := derivedChecksIn(runDismissalScan(st, batch)); len(got) != 0 {
		t.Fatalf("carried evidence raised %v", got)
	}
	source.ScanCarryForward = false
	requireChangedContentAggregates(t, st, batch)
}

func derivedChecksIn(findings []alert.Finding) []string {
	var out []string
	for _, f := range findings {
		if IsDerivedCorrelationCheck(f.Check) {
			out = append(out, f.Check)
		}
	}
	return out
}

func TestCorrelationWithInitiallyUnknownDismissedContent(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	st := newTestStore(t)
	batch := dismissalCorrelationBatch()
	st.SetBaseline(batch[1:2])
	batch[1].ContentSHA256 = strings.Repeat("a", 64)
	if got := derivedChecksIn(runDismissalScan(st, batch)); len(got) != 0 {
		t.Fatalf("first known content raised %v", got)
	}
	changed := batch[1]
	changed.ContentSHA256 = strings.Repeat("b", 64)
	batch = append(batch, changed)
	requireChangedContentAggregates(t, st, batch)
	if entry, ok := st.EntryForKey(changed.Key()); !ok || !entry.IsBaseline || entry.ContentSHA256 != "" {
		t.Errorf("correlation changed the dismissal before dispatch: %+v", entry)
	}
}

func TestStoredCorrelationUsesRetainedContentEvidence(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	st := newTestStore(t)
	batch := dismissalCorrelationBatch()
	st.SetBaseline(batch[1:2])
	batch[1].ContentSHA256 = strings.Repeat("a", 64)
	StoreLatestScanFindings(st, nil, batch)
	other := batch[1]
	other.ContentSHA256 = strings.Repeat("b", 64)
	other.FilePath = "/home/bob/public_html/other.php"
	// This key collides with a row whose path the scan could not examine.
	// The merge retains the original row, which supplied no fresh content.
	gaps := map[string]map[string]bool{"webshell": {batch[1].FilePath: true}}
	StoreLatestScanFindingsWithGaps(st, nil, []alert.Finding{other}, gaps)
	latest := st.LatestFindings()
	if got := derivedChecksIn(latest); len(got) != 0 {
		t.Errorf("one fresh observation for an unknown dismissal raised %v from a retained row", got)
	}
	for _, f := range latest {
		if f.Key() == other.Key() && f.FilePath == batch[1].FilePath && f.ContentSHA256 == batch[1].ContentSHA256 {
			return
		}
	}
	t.Fatal("merge lost the row from the unexamined path")
}

func TestDismissedFindingsLeaveStoredCorrelation(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	st := newTestStore(t)
	batch := dismissalCorrelationBatch()
	StoreLatestScanFindings(st, []string{"webshell", "db_rogue_admin"}, batch)
	if got := derivedChecksIn(st.LatestFindings()); len(got) != 2 {
		t.Fatalf("fixture must raise both aggregates before the dismissal, got %v", got)
	}
	st.Update(batch)
	st.DismissFindingWithUndo(batch[1].Key())
	StoreLatestScanFindings(st, []string{"webshell", "db_rogue_admin"}, batch)
	latest := st.LatestFindings()
	if got := derivedChecksIn(latest); len(got) != 0 {
		t.Fatalf("stored list keeps %v built from a dismissed finding", got)
	}
	for _, f := range latest {
		if f.Key() == batch[1].Key() {
			return
		}
	}
	t.Fatal("repeat scan did not relist the dismissed source")
}

func TestDismissedFindingsLeaveScanCorrelation(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	st := newTestStore(t)
	batch := dismissalCorrelationBatch()
	st.Update(batch)
	st.DismissFinding(batch[1].Key())
	rows := runDismissalScan(st, dismissalCorrelationBatch())
	if got := derivedChecksIn(rows); len(got) != 0 {
		t.Fatalf("scan raised %v from a dismissed finding", got)
	}
	// Without a store there is nothing dismissed, and the batch still correlates.
	rows = runDismissalScan(nil, dismissalCorrelationBatch())
	if got := derivedChecksIn(rows); len(got) != 2 {
		t.Fatalf("scan without a store raised %v, want both aggregates", got)
	}
}
