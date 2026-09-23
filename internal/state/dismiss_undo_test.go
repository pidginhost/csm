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
