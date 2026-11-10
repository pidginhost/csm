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
	if !s.DismissFindingIfLatest(f) {
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
