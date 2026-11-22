package checks

import (
	"context"
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

func derivedChecksIn(findings []alert.Finding) []string {
	var out []string
	for _, f := range findings {
		if IsDerivedCorrelationCheck(f.Check) {
			out = append(out, f.Check)
		}
	}
	return out
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
	st.DismissFinding(batch[1].Key())
	StoreLatestScanFindings(st, []string{"webshell", "db_rogue_admin"}, batch)
	if got := derivedChecksIn(st.LatestFindings()); len(got) != 0 {
		t.Fatalf("stored list keeps %v built from a dismissed finding", got)
	}
}

func TestDismissedFindingsLeaveScanCorrelation(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	st := newTestStore(t)
	batch := dismissalCorrelationBatch()
	st.Update(batch)
	st.DismissFinding(batch[1].Key())
	rows, _ := runParallel(&config.Config{}, st, []namedCheck{{name: "webshell", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		return dismissalCorrelationBatch()
	}}}, "test", true)
	if got := derivedChecksIn(rows); len(got) != 0 {
		t.Fatalf("scan raised %v from a dismissed finding", got)
	}
	// Without a store there is nothing dismissed, and the batch still correlates.
	rows, _ = runParallel(&config.Config{}, nil, []namedCheck{{name: "webshell", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		return dismissalCorrelationBatch()
	}}}, "test", true)
	if got := derivedChecksIn(rows); len(got) != 2 {
		t.Fatalf("scan without a store raised %v, want both aggregates", got)
	}
}
