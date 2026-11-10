package state

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A finding the re-verifier resolved is gone, not accepted. The same
// detection at the same path later is new evidence and must alert.
func TestVerifiedResolvedFindingAlertsOnReturn(t *testing.T) {
	s := openTestStore(t)
	f := dismissTestFinding()
	f.ContentSHA256 = "aaaa"
	s.Update([]alert.Finding{f})
	s.SetLatestFindings([]alert.Finding{f})
	if !s.PrepareFindingResolution(f)() {
		t.Fatal("verified snapshot was not cleared")
	}
	if n := len(s.LatestFindings()); n != 0 {
		t.Fatalf("resolved finding still listed: %d", n)
	}
	if n := len(s.FilterNew([]alert.Finding{f})); n != 1 {
		t.Fatalf("return after verified resolution suppressed: %d new", n)
	}
	if s.Acknowledged(f) {
		t.Fatal("resolved finding reported as acknowledged")
	}
}

func TestRearmFindingsKeepsInternalKeys(t *testing.T) {
	s := openTestStore(t)
	s.SetRaw("_probe:cursor", "1")
	s.RearmFindings([]string{"_probe:cursor"})
	if _, ok := s.GetRaw("_probe:cursor"); !ok {
		t.Fatal("re-arming deleted internal housekeeping state")
	}
}

func TestResolvedFindingPersistsRearming(t *testing.T) {
	s := openTestStore(t)
	f := dismissTestFinding()
	s.Update([]alert.Finding{f})
	s.SetLatestFindings([]alert.Finding{f})
	deliver(s, f)
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if !s.PrepareFindingResolution(f)() {
		t.Fatal("resolution rejected")
	}
	reopened, err := Open(s.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if len(reopened.LatestFindings()) != 0 {
		t.Fatal("resolved finding restored after restart")
	}
	if len(reopened.FilterNew([]alert.Finding{f})) != 1 {
		t.Fatal("resolution lost alert rearming after restart")
	}
	if len(offered(reopened, f)) != 1 {
		t.Fatal("resolution lost email rearming after restart")
	}
}

func TestResolutionInvalidatesDeliveryAndDismissalReceipts(t *testing.T) {
	s := openTestStore(t)
	f := dismissTestFinding()
	s.Update([]alert.Finding{f})
	s.SetLatestFindings([]alert.Finding{f})
	pending, finishOld := s.BeginDelivery([]alert.Finding{f})
	if len(pending) != 1 {
		t.Fatal("first delivery not selected")
	}
	undo := s.DismissFindingWithUndo(f.Key())
	s.SetLatestFindings([]alert.Finding{f})
	if !s.PrepareFindingResolution(f)() {
		t.Fatal("resolution rejected")
	}
	if s.UndoDismiss(undo) {
		t.Fatal("old undo resurrected resolved finding")
	}
	if len(s.FilterNew([]alert.Finding{f})) != 1 {
		t.Fatal("return not new")
	}
	returned, finishNew := s.BeginDelivery([]alert.Finding{f})
	if len(returned) != 1 {
		t.Fatal("old email blocked returning finding")
	}
	finishOld(pending)
	if e, _ := s.EntryForKey(f.Key()); e.Emailed != "" {
		t.Fatal("old delivery acknowledged returning finding")
	}
	overlap, finishOverlap := s.BeginDelivery([]alert.Finding{f})
	finishOverlap(nil)
	if len(overlap) != 0 {
		t.Fatal("old delivery released new reservation")
	}
	finishNew(returned)
	if len(offered(s, f)) != 0 {
		t.Fatal("current delivery receipt lost")
	}
}

// A realtime finding need not have reached the latest list or alert state
// before remediation starts. Email delivery creates receipts, not evidence.
func TestResolutionOfUnlistedFindingWithPendingDelivery(t *testing.T) {
	s := openTestStore(t)
	f := dismissTestFinding()
	resolve := s.PrepareFindingResolution(f)
	pending, finish := s.BeginDelivery([]alert.Finding{f})
	if len(pending) != 1 {
		t.Fatal("delivery not selected")
	}
	if !resolve() {
		t.Fatal("delivery prevented resolution of unlisted finding")
	}
	finish(pending)
	if len(s.FilterNew([]alert.Finding{f})) != 1 {
		t.Fatal("late delivery restored resolved state")
	}
}

func TestResolutionRejectsLaterAlertObservation(t *testing.T) {
	s := openTestStore(t)
	f := dismissTestFinding()
	resolve := s.PrepareFindingResolution(f)
	s.Update([]alert.Finding{f})
	if resolve() {
		t.Fatal("resolution cleared an observation recorded after capture")
	}
	if _, ok := s.EntryForKey(f.Key()); !ok {
		t.Fatal("new alert state missing")
	}
}

func TestResolutionPreservesLaterDecisionAndAcceptsDelivery(t *testing.T) {
	for _, change := range []string{"observation", "dismissal", "baseline", "delivery"} {
		t.Run(change, func(t *testing.T) {
			s := openTestStore(t)
			f := dismissTestFinding()
			s.Update([]alert.Finding{f})
			s.SetLatestFindings([]alert.Finding{f})
			resolve := s.PrepareFindingResolution(f)
			switch change {
			case "observation":
				s.Update([]alert.Finding{f})
			case "dismissal":
				s.DismissFindingWithUndo(f.Key())
				s.SetLatestFindings([]alert.Finding{f})
			case "baseline":
				s.SetBaseline([]alert.Finding{f})
			case "delivery":
				deliver(s, f)
			}
			wantResolved := change == "delivery"
			if got := resolve(); got != wantResolved {
				t.Fatalf("resolved=%v after %s", got, change)
			}
			wantLatest := 1
			if wantResolved {
				wantLatest = 0
			}
			if got := len(s.LatestFindings()); got != wantLatest {
				t.Fatalf("latest count=%d after %s", got, change)
			}
			if _, ok := s.EntryForKey(f.Key()); ok == wantResolved {
				t.Fatalf("entry present=%v after %s", ok, change)
			}
		})
	}
}
