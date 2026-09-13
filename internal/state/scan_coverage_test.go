package state

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestScopedCoverageMergeUsesCurrentStateAndPersists(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first := time.Unix(100, 0)
	row := func(key, scope string) alert.Finding {
		return alert.Finding{Check: "db_post_injection", DedupKey: key, CoverageScope: scope, Message: key, Severity: alert.High, Timestamp: first}
	}
	resolved, live, failed, dismissed, legacy := row("resolved", "done"), row("live", "done"), row("failed", "unknown"), row("dismissed", "unknown"), row("legacy", "")
	s.PurgeAndMergeFindings(nil, []alert.Finding{resolved, live, failed, dismissed, legacy})
	// A partial scan carries no old rows. A refresh and dismissal occurring
	// while it runs must therefore remain authoritative in the merge.
	failed.Details = "refreshed during scan"
	failed.Timestamp = time.Unix(200, 0)
	s.PurgeAndMergeFindings(nil, []alert.Finding{failed})
	s.DismissLatestFinding(dismissed.Key())
	live.Timestamp = time.Unix(300, 0)
	coverage := &ScanCoverage{CompletedScopes: map[string]map[string]bool{"db_post_injection": {"done": true}}}
	s.PurgeAndMergeFindingsDerivedWithCoverage(nil, []alert.Finding{live}, coverage, nil, func(merged []alert.Finding) []alert.Finding {
		if len(merged) != 3 {
			t.Errorf("correlation saw %d rows, want live, failed and legacy", len(merged))
		}
		return nil
	})
	if closeErr := s.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	got := make(map[string]alert.Finding)
	for _, f := range s.LatestFindings() {
		got[f.Key()] = f
	}
	if len(got) != 3 {
		t.Fatalf("stored rows = %+v", got)
	}
	for _, f := range []alert.Finding{live, failed, legacy} {
		stored, ok := got[f.Key()]
		if !ok || stored.CoverageScope != f.CoverageScope || !stored.Timestamp.Equal(f.Timestamp) || stored.Details != f.Details || !stored.FirstSeen.Equal(first) {
			t.Errorf("stored state changed: got %+v, want %+v with original first-seen", stored, f)
		}
	}
	// A complete owner scan can retire records from before scope attribution.
	s.PurgeAndMergeFindings([]string{"db_post_injection"}, nil)
	if len(s.LatestFindings()) != 0 {
		t.Fatal("complete scan retained legacy state")
	}
}

func TestScopedCoverageDoesNotEvictUnexaminedFindings(t *testing.T) {
	s := openTestStore(t)
	old := alert.Finding{Check: "db_post_injection", DedupKey: "unexamined", Severity: alert.Warning, CoverageScope: "failed"}
	s.PurgeAndMergeFindings(nil, []alert.Finding{old})
	fresh := make([]alert.Finding, latestFindingsCap)
	for i := range fresh {
		fresh[i] = alert.Finding{Check: "db_post_injection", DedupKey: fmt.Sprint(i), CoverageScope: "done", Severity: alert.High}
	}
	coverage := &ScanCoverage{CompletedScopes: map[string]map[string]bool{"db_post_injection": {"done": true}}}
	s.PurgeAndMergeFindingsDerivedWithCoverage(nil, fresh, coverage, nil, func([]alert.Finding) []alert.Finding { return nil })
	for _, f := range s.LatestFindings() {
		if f.Key() == old.Key() {
			return
		}
	}
	t.Fatal("active-set cap retired an unexamined finding during scoped replacement")
}

func TestPartialCoverageCannotGrowActiveSetBeyondCap(t *testing.T) {
	for _, derived := range []bool{false, true} {
		t.Run(fmt.Sprint(derived), func(t *testing.T) {
			s := openTestStore(t)
			old := alert.Finding{Check: "db_post_injection", DedupKey: "old", Severity: alert.Warning, Timestamp: time.Unix(100, 0)}
			s.PurgeAndMergeFindings(nil, []alert.Finding{old})
			coverage := &ScanCoverage{IncompleteChecks: map[string]bool{"db_post_injection": true}}
			for cycle := range 3 {
				fresh := make([]alert.Finding, latestFindingsCap)
				for i := range fresh {
					fresh[i] = alert.Finding{Check: old.Check, DedupKey: fmt.Sprintf("%d/%d", cycle, i), CoverageScope: "partial", Severity: alert.High}
				}
				old.Details = fmt.Sprintf("refreshed %d", cycle)
				fresh = append(fresh, old)
				var derive func([]alert.Finding) []alert.Finding
				if derived {
					derive = func([]alert.Finding) []alert.Finding { return nil }
				}
				s.PurgeAndMergeFindingsDerivedWithCoverage(nil, fresh, coverage, nil, derive)
				latest := s.LatestFindings()
				if len(latest) > latestFindingsCap {
					t.Fatalf("cycle %d grew active set to %d", cycle, len(latest))
				}
				found := false
				for _, f := range latest {
					if f.Key() == old.Key() {
						found = f.Details == old.Details && f.FirstSeen.Equal(old.Timestamp)
					}
				}
				if !found {
					t.Fatal("bounded merge lost retained finding or its refresh")
				}
			}
		})
	}
}
