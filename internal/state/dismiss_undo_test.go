package state

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func dismissTestFinding() alert.Finding {
	return alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "Webshell found", FilePath: "/home/a/public_html/x.php"}
}

func TestDismissFindingWithUndoRoundTrip(t *testing.T) {
	s := openTestStore(t)
	f := dismissTestFinding()
	s.Update([]alert.Finding{f})
	s.SetLatestFindings([]alert.Finding{f})

	u := s.DismissFindingWithUndo(f.Key())
	if e, _ := s.EntryForKey(f.Key()); !e.IsBaseline {
		t.Fatal("dismiss must mark the entry as baseline")
	}
	if n := len(s.LatestFindings()); n != 0 {
		t.Fatalf("dismissed finding still listed: %d", n)
	}

	s.UndoDismiss(u)
	if e, _ := s.EntryForKey(f.Key()); e.IsBaseline {
		t.Fatal("undo must re-arm alerts for the finding")
	}
	latest := s.LatestFindings()
	if len(latest) != 1 || latest[0].Key() != f.Key() {
		t.Fatalf("undo must list the finding again, got %+v", latest)
	}
}

// Undo returns the entry to the state it had before the dismissal: a finding
// that was already part of the install baseline stays baseline.
func TestUndoDismissKeepsEarlierBaseline(t *testing.T) {
	s := openTestStore(t)
	f := dismissTestFinding()
	s.SetBaseline([]alert.Finding{f})
	s.SetLatestFindings([]alert.Finding{f})

	u := s.DismissFindingWithUndo(f.Key())
	s.UndoDismiss(u)
	if e, _ := s.EntryForKey(f.Key()); !e.IsBaseline {
		t.Fatal("undo must not clear a baseline that predates the dismissal")
	}
	if n := len(s.LatestFindings()); n != 1 {
		t.Fatalf("latest = %d, want the finding restored", n)
	}
}

// A scan that re-reports the finding before the undo runs must not end up
// with the finding listed twice, and the newer scan copy wins.
func TestUndoDismissDoesNotDuplicateAReportedFinding(t *testing.T) {
	s := openTestStore(t)
	f := dismissTestFinding()
	s.Update([]alert.Finding{f})
	s.SetLatestFindings([]alert.Finding{f})
	u := s.DismissFindingWithUndo(f.Key())

	newer := f
	newer.Timestamp = time.Now().Add(time.Minute)
	s.SetLatestFindings([]alert.Finding{newer})
	s.UndoDismiss(u)

	latest := s.LatestFindings()
	if len(latest) != 1 {
		t.Fatalf("latest = %d findings, want 1", len(latest))
	}
	if !latest[0].Timestamp.Equal(newer.Timestamp) {
		t.Fatalf("undo replaced the newer scan copy: %+v", latest[0])
	}
}

func TestDismissFindingWithUndoOnUnknownKeyIsInert(t *testing.T) {
	s := openTestStore(t)
	u := s.DismissFindingWithUndo("webshell:nothing")
	if len(u.Removed) != 0 || u.ClearBaseline {
		t.Fatalf("undo record for an unknown key should be empty: %+v", u)
	}
	s.UndoDismiss(u)
	if _, ok := s.EntryForKey("webshell:nothing"); ok {
		t.Fatal("undo must not create state for an unknown key")
	}
}

func TestUndoDismissPreservesLaterDecisions(t *testing.T) {
	for _, later := range []string{"dismiss", "dismiss-with-undo", "verified", "baseline"} {
		t.Run(later, func(t *testing.T) {
			s := openTestStore(t)
			f := dismissTestFinding()
			s.Update([]alert.Finding{f})
			s.SetLatestFindings([]alert.Finding{f})
			u := s.DismissFindingWithUndo(f.Key())
			s.SetLatestFindings([]alert.Finding{f})
			switch later {
			case "dismiss":
				s.DismissFinding(f.Key())
				s.DismissLatestFinding(f.Key())
			case "dismiss-with-undo":
				s.DismissFindingWithUndo(f.Key())
			case "verified":
				if !s.DismissFindingIfLatest(f) {
					t.Fatal("verification did not dismiss finding")
				}
			case "baseline":
				s.SetBaseline([]alert.Finding{f})
				s.ClearLatestFindings()
			}
			s.UndoDismiss(u)
			if e, _ := s.EntryForKey(f.Key()); !e.IsBaseline {
				t.Fatal("undo cleared a later baseline decision")
			}
			if len(s.LatestFindings()) != 0 {
				t.Fatal("undo resurrected a finding removed by a later decision")
			}
		})
	}
}

func TestDismissLatestOnlyFindingStopsAlertsAndUndoRestoresThem(t *testing.T) {
	s := openTestStore(t)
	f := dismissTestFinding()
	s.SetLatestFindings([]alert.Finding{f})
	u := s.DismissFindingWithUndo(f.Key())
	if len(s.FilterNew([]alert.Finding{f})) != 0 {
		t.Fatal("latest-only finding still alerts after dismissal")
	}
	s.Update([]alert.Finding{f})
	s.UndoDismiss(u)
	if len(s.FilterNew([]alert.Finding{f})) != 1 {
		t.Fatal("undo did not restore latest-only alert state")
	}
}

func TestDismissUndoSurvivesStoreReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := dismissTestFinding()
	s.Update([]alert.Finding{f})
	s.SetLatestFindings([]alert.Finding{f})
	u := s.DismissFindingWithUndo(f.Key())
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if !s.UndoDismiss(u) {
		t.Fatal("dismiss identity did not survive reopening the store")
	}
	if e, _ := s.EntryForKey(f.Key()); e.IsBaseline {
		t.Fatal("reopened undo kept the dismissed baseline")
	}
	if len(s.LatestFindings()) != 1 {
		t.Fatal("reopened undo lost the finding")
	}
}
