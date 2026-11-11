package state

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

var (
	shaA = strings.Repeat("a", 64)
	shaB = strings.Repeat("b", 64)
)

func contentFinding(check, sha string) alert.Finding {
	return alert.Finding{Check: check, Severity: alert.Critical,
		Message:  "YARA rule match [webshell_generic]: /home/a/public_html/x.php",
		Details:  "Scheduled deep scan matched YARA rule webshell_generic",
		FilePath: "/home/a/public_html/x.php", ContentSHA256: sha}
}

func TestContentDoesNotChangeFindingIdentity(t *testing.T) {
	a := contentFinding("yara_match_scheduled", shaA)
	for _, content := range []string{"", shaB} {
		other := contentFinding(a.Check, content)
		if other.Key() != a.Key() || other.Fingerprint() != a.Fingerprint() {
			t.Fatal("content changed the finding key or fingerprint")
		}
	}
}

func TestBaselinePreservesKnownContent(t *testing.T) {
	a := contentFinding("yara_match_scheduled", shaA)
	b := contentFinding("yara_match_scheduled", shaB)
	unknown := contentFinding("yara_match_scheduled", "")
	for _, tc := range []struct {
		name     string
		previous []alert.Finding
		findings []alert.Finding
		want     string
	}{
		{name: "duplicate unknown last", findings: []alert.Finding{a, unknown}, want: shaA},
		{name: "duplicate known last", findings: []alert.Finding{unknown, a}, want: shaA},
		{name: "reset with unknown", previous: []alert.Finding{a}, findings: []alert.Finding{unknown}, want: shaA},
		{name: "reset with new content", previous: []alert.Finding{a}, findings: []alert.Finding{b}, want: shaB},
		{name: "new content before unknown", previous: []alert.Finding{a}, findings: []alert.Finding{b, unknown}, want: shaB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			s.SetBaseline(tc.previous)
			s.SetBaseline(tc.findings)
			e, ok := s.EntryForKey(a.Key())
			if !ok || !e.IsBaseline || e.ContentSHA256 != tc.want {
				t.Fatalf("baseline = %+v, present %v; want content %q", e, ok, tc.want)
			}
			changed := a
			if tc.want == shaA {
				changed = b
			}
			s.ReconcileDismissedContent([]alert.Finding{changed})
			if len(s.FilterNew([]alert.Finding{changed})) != 1 {
				t.Fatal("changed content was silently adopted instead of alerting")
			}
		})
	}
}

func TestReconcileIgnoresCarriedContent(t *testing.T) {
	for _, tc := range []struct{ name, recorded string }{
		{name: "legacy"},
		{name: "known", recorded: shaB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			s.SetBaseline([]alert.Finding{contentFinding("yara_match_scheduled", tc.recorded)})
			carried := contentFinding("yara_match_scheduled", shaA)
			carried.ScanCarryForward = true

			s.ReconcileDismissedContent([]alert.Finding{carried})

			e, ok := s.EntryForKey(carried.Key())
			if !ok || !e.IsBaseline || e.ContentSHA256 != tc.recorded {
				t.Fatalf("baseline = %+v, present %v; an unexamined snapshot must not adopt or revoke content", e, ok)
			}
			if s.dirty {
				t.Fatal("ignored snapshot dirtied the saved baseline")
			}
		})
	}
}

func TestReconcileRevokesBaselineOnChangedContent(t *testing.T) {
	// suspicious_php_content keeps Details identical: a rewrite that keeps
	// size and mtime yields the same Key and Fingerprint, only new bytes.
	for _, check := range []string{"yara_match_scheduled", "suspicious_php_content", "docroot_binary_exec"} {
		t.Run(check, func(t *testing.T) {
			s := openTestStore(t)
			a, b := contentFinding(check, shaA), contentFinding(check, shaB)
			s.SetBaseline([]alert.Finding{a})

			s.ReconcileDismissedContent([]alert.Finding{b})

			if _, ok := s.EntryForKey(b.Key()); ok {
				t.Fatal("dismissal must end when the content changes")
			}
			if n := len(s.FilterNew([]alert.Finding{b})); n != 1 {
				t.Fatalf("changed content must be new, FilterNew returned %d", n)
			}
		})
	}
}

func TestReconcileKeepsBaselineOnSameContent(t *testing.T) {
	s := openTestStore(t)
	a := contentFinding("yara_match_scheduled", shaA)
	s.SetBaseline([]alert.Finding{a})

	s.ReconcileDismissedContent([]alert.Finding{a})

	if n := len(s.FilterNew([]alert.Finding{a})); n != 0 {
		t.Fatalf("same content must stay dismissed, FilterNew returned %d", n)
	}
	e, ok := s.EntryForKey(a.Key())
	if !ok || !e.IsBaseline || e.ContentSHA256 != shaA {
		t.Fatalf("entry = %+v, ok %v; want baseline with content A", e, ok)
	}
}

func TestReconcileIgnoresEmptyContent(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{name: "legacy"},
		{name: "known", content: shaA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			a := contentFinding("yara_match_scheduled", tc.content)
			s.SetBaseline([]alert.Finding{a})

			s.ReconcileDismissedContent([]alert.Finding{contentFinding("yara_match_scheduled", "")})

			e, ok := s.EntryForKey(a.Key())
			if !ok || !e.IsBaseline || e.ContentSHA256 != tc.content {
				t.Fatalf("entry = %+v, ok %v; an unknown hash must not revoke or overwrite", e, ok)
			}
			if s.dirty {
				t.Fatal("unknown content dirtied the saved baseline")
			}
		})
	}
}

func TestReconcileAdoptsContentForLegacyDismissal(t *testing.T) {
	s := openTestStore(t)
	legacy := contentFinding("yara_match_scheduled", "")
	s.SetBaseline([]alert.Finding{legacy})
	a := contentFinding("yara_match_scheduled", shaA)

	s.ReconcileDismissedContent([]alert.Finding{a})

	e, ok := s.EntryForKey(a.Key())
	if !ok || !e.IsBaseline || e.ContentSHA256 != shaA {
		t.Fatalf("entry = %+v, ok %v; want content A adopted", e, ok)
	}
	if n := len(s.FilterNew([]alert.Finding{a})); n != 0 {
		t.Fatalf("adoption must stay silent, FilterNew returned %d", n)
	}

	s.ReconcileDismissedContent([]alert.Finding{contentFinding("yara_match_scheduled", shaB)})

	if _, ok := s.EntryForKey(a.Key()); ok {
		t.Fatal("a change after adoption must end the dismissal")
	}
}

func TestReconcileLeavesActiveEntries(t *testing.T) {
	s := openTestStore(t)
	a := contentFinding("yara_match_scheduled", shaA)
	s.Update([]alert.Finding{a})

	s.ReconcileDismissedContent([]alert.Finding{contentFinding("yara_match_scheduled", shaB)})

	e, ok := s.EntryForKey(a.Key())
	if !ok || e.IsBaseline || e.ContentSHA256 != "" {
		t.Fatalf("entry = %+v, ok %v; an undismissed entry must be left alone", e, ok)
	}
}

func TestRevokedDismissalIsOfferedForDelivery(t *testing.T) {
	s := openTestStore(t)
	a, b := contentFinding("yara_match_scheduled", shaA), contentFinding("yara_match_scheduled", shaB)
	s.Update([]alert.Finding{a})
	eligible, finish := s.BeginDelivery([]alert.Finding{a})
	finish(eligible)
	s.SetLatestFindings([]alert.Finding{a})
	s.DismissFindingWithUndo(a.Key())
	s.ReconcileDismissedContent([]alert.Finding{a})

	s.ReconcileDismissedContent([]alert.Finding{b})

	if _, ok := s.EntryForKey(b.Key()); ok {
		t.Fatal("revocation retained the old alert and delivery receipts")
	}
	eligible, finish = s.BeginDelivery([]alert.Finding{b})
	defer finish(nil)
	if len(eligible) != 1 {
		t.Fatalf("changed content must be offered to email, got %d", len(eligible))
	}
}

func TestRevocationInvalidatesPendingDelivery(t *testing.T) {
	s := openTestStore(t)
	a, b := contentFinding("yara_match_scheduled", shaA), contentFinding("yara_match_scheduled", shaB)
	s.Update([]alert.Finding{a})
	pending, finishOld := s.BeginDelivery([]alert.Finding{a})
	defer finishOld(nil)
	if len(pending) != 1 {
		t.Fatal("first delivery not selected")
	}
	s.SetLatestFindings([]alert.Finding{a})
	undo := s.DismissFindingWithUndo(a.Key())
	s.ReconcileDismissedContent([]alert.Finding{a})
	s.ReconcileDismissedContent([]alert.Finding{b})
	if s.UndoDismiss(undo) {
		t.Fatal("old undo restored a revoked dismissal")
	}

	returned, finishNew := s.BeginDelivery([]alert.Finding{b})
	defer finishNew(nil)
	if len(returned) != 1 {
		t.Fatal("old delivery blocked changed content")
	}
	finishOld(pending)
	if e, _ := s.EntryForKey(b.Key()); e.Emailed != "" {
		t.Fatal("old completion marked changed content delivered")
	}
	overlap, finishOverlap := s.BeginDelivery([]alert.Finding{b})
	finishOverlap(nil)
	if len(overlap) != 0 {
		t.Fatal("old completion released the new delivery reservation")
	}
	finishNew(returned)
	if len(offered(s, b)) != 0 {
		t.Fatal("new delivery receipt was lost")
	}
	if len(s.emailPending) != 0 {
		t.Fatal("completed deliveries left pending reservations")
	}
}

func TestReconcileRevokesWhenBatchCarriesTwoContents(t *testing.T) {
	s := openTestStore(t)
	a, b := contentFinding("yara_match_scheduled", shaA), contentFinding("yara_match_scheduled", shaB)
	s.SetBaseline([]alert.Finding{a})

	s.ReconcileDismissedContent([]alert.Finding{a, b})

	if _, ok := s.EntryForKey(a.Key()); ok {
		t.Fatal("any differing content in the batch must end the dismissal")
	}
}

func TestResolutionStartedBeforeRevocationKeepsNewDetection(t *testing.T) {
	for _, recreate := range []bool{false, true} {
		name := "deleted"
		if recreate {
			name = "recreated"
		}
		t.Run(name, func(t *testing.T) {
			s := openTestStore(t)
			a, b := contentFinding("yara_match_scheduled", shaA), contentFinding("yara_match_scheduled", shaB)
			s.SetBaseline([]alert.Finding{a})
			s.SetLatestFindings([]alert.Finding{a})
			resolve := s.PrepareFindingResolution(a)

			s.ReconcileDismissedContent([]alert.Finding{b})
			if recreate {
				eligible, finish := s.BeginDelivery([]alert.Finding{b})
				defer finish(nil)
				if len(eligible) != 1 {
					t.Fatal("changed content was not offered for delivery")
				}
			}
			// Keep the listing and observation unchanged so rejection cannot
			// rely on Update or the latest merge having recorded B.
			if resolve() {
				t.Fatal("a resolution started before revocation must be rejected")
			}
			e, ok := s.EntryForKey(b.Key())
			if ok != recreate || e.IsBaseline {
				t.Fatalf("entry = %+v, ok %v; want present %v without a baseline", e, ok, recreate)
			}
			if len(s.LatestFindings()) != 1 {
				t.Fatal("old resolution removed the listing")
			}
		})
	}
}

func TestDismissedContentSurvivesReopen(t *testing.T) {
	for _, operation := range []string{"baseline", "adoption", "revocation"} {
		t.Run(operation, func(t *testing.T) {
			s := openTestStore(t)
			a := contentFinding("yara_match_scheduled", shaA)
			if operation == "adoption" {
				s.SetBaseline([]alert.Finding{contentFinding(a.Check, "")})
				s.ReconcileDismissedContent([]alert.Finding{a})
			} else {
				s.SetBaseline([]alert.Finding{a})
			}
			if operation == "revocation" {
				s.ReconcileDismissedContent([]alert.Finding{contentFinding(a.Check, shaB)})
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			reopened, err := Open(s.path)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			e, ok := reopened.EntryForKey(a.Key())
			if operation == "revocation" {
				if ok || len(reopened.FilterNew([]alert.Finding{a})) != 1 {
					t.Fatal("revoked dismissal returned after reopen")
				}
			} else if !ok || !e.IsBaseline || e.ContentSHA256 != shaA {
				t.Fatalf("entry after reopen = %+v, present %v; want baseline with content A", e, ok)
			}
		})
	}
}

func listedContentFinding(t *testing.T, s *Store, sha string) alert.Finding {
	t.Helper()
	f := contentFinding("yara_match_scheduled", sha)
	s.Update([]alert.Finding{f})
	s.SetLatestFindings([]alert.Finding{f})
	return f
}

func TestDismissRecordsListedRowContent(t *testing.T) {
	s := openTestStore(t)
	a := listedContentFinding(t, s, shaA)

	s.DismissFindingWithUndo(a.Key())

	if e, _ := s.EntryForKey(a.Key()); !e.IsBaseline || e.ContentSHA256 != shaA {
		t.Fatalf("entry = %+v; want baseline with the listed content", e)
	}
}

func TestDismissAsShownRefusesChangedRow(t *testing.T) {
	s := openTestStore(t)
	b := listedContentFinding(t, s, shaB)

	if _, ok := s.DismissFindingAsShown(b.Key(), shaA); ok {
		t.Fatal("a row whose content changed since it was shown must not be dismissed")
	}
	if e, _ := s.EntryForKey(b.Key()); e.IsBaseline || e.DismissalID != "" {
		t.Fatalf("refusal changed the entry: %+v", e)
	}
	if latest := s.LatestFindings(); len(latest) != 1 || latest[0].ContentSHA256 != shaB {
		t.Fatalf("refusal changed the list: %+v", latest)
	}
}

func TestDismissAsShownTreatsEmptyAgainstHashAsChanged(t *testing.T) {
	t.Run("row hash, shown empty", func(t *testing.T) {
		s := openTestStore(t)
		b := listedContentFinding(t, s, shaB)
		if _, ok := s.DismissFindingAsShown(b.Key(), ""); ok {
			t.Fatal("shown empty against a hashed row must be refused")
		}
	})
	t.Run("row empty, shown hash", func(t *testing.T) {
		s := openTestStore(t)
		f := listedContentFinding(t, s, "")
		if _, ok := s.DismissFindingAsShown(f.Key(), shaA); ok {
			t.Fatal("shown hash against an unhashed row must be refused")
		}
	})
}

func TestDismissAsShownAcceptsBothEmpty(t *testing.T) {
	s := openTestStore(t)
	f := dismissTestFinding()
	s.Update([]alert.Finding{f})
	s.SetLatestFindings([]alert.Finding{f})

	if _, ok := s.DismissFindingAsShown(f.Key(), ""); !ok {
		t.Fatal("a finding without content must be dismissable")
	}
	if e, _ := s.EntryForKey(f.Key()); !e.IsBaseline || e.ContentSHA256 != "" {
		t.Fatalf("entry = %+v; want baseline without content", e)
	}
}

func TestDismissAsShownRecordsShownWhenUnlisted(t *testing.T) {
	s := openTestStore(t)
	a := contentFinding("yara_match_scheduled", shaA)
	s.Update([]alert.Finding{a})

	if _, ok := s.DismissFindingAsShown(a.Key(), shaA); !ok {
		t.Fatal("an unlisted finding must be dismissable")
	}
	if e, _ := s.EntryForKey(a.Key()); !e.IsBaseline || e.ContentSHA256 != shaA {
		t.Fatalf("entry = %+v; want the shown content recorded", e)
	}
}

func TestRedismissKeepsRecordedContent(t *testing.T) {
	s := openTestStore(t)
	a := contentFinding("yara_match_scheduled", shaA)
	s.SetBaseline([]alert.Finding{a})
	s.SetLatestFindings([]alert.Finding{a})

	if _, ok := s.DismissFindingAsShown(a.Key(), shaA); !ok {
		t.Fatal("re-dismissing a re-listed finding with the same content must be accepted")
	}
	if e, _ := s.EntryForKey(a.Key()); e.ContentSHA256 != shaA {
		t.Fatalf("recorded content = %q, want A", e.ContentSHA256)
	}

	s.DismissFindingWithUndo(a.Key())

	if e, _ := s.EntryForKey(a.Key()); !e.IsBaseline || e.ContentSHA256 != shaA {
		t.Fatalf("entry = %+v; a dismissal with no content must keep the recorded one", e)
	}
}

func TestUndoRestoresPreviousContent(t *testing.T) {
	t.Run("active finding", func(t *testing.T) {
		s := openTestStore(t)
		a := listedContentFinding(t, s, shaA)
		u := s.DismissFindingWithUndo(a.Key())

		if !s.UndoDismiss(u) {
			t.Fatal("undo refused")
		}
		if e, _ := s.EntryForKey(a.Key()); e.IsBaseline || e.ContentSHA256 != "" {
			t.Fatalf("entry = %+v; want active without recorded content", e)
		}
	})
	t.Run("baseline from before content was recorded", func(t *testing.T) {
		s := openTestStore(t)
		s.SetBaseline([]alert.Finding{contentFinding("yara_match_scheduled", "")})
		a := contentFinding("yara_match_scheduled", shaA)
		s.SetLatestFindings([]alert.Finding{a})
		u, ok := s.DismissFindingAsShown(a.Key(), shaA)
		if !ok {
			t.Fatal("dismiss refused")
		}

		if !s.UndoDismiss(u) {
			t.Fatal("undo refused")
		}
		if e, _ := s.EntryForKey(a.Key()); !e.IsBaseline || e.ContentSHA256 != "" {
			t.Fatalf("entry = %+v; want the earlier baseline without content", e)
		}
	})
}

func TestUndoAfterRevocationFails(t *testing.T) {
	s := openTestStore(t)
	a := listedContentFinding(t, s, shaA)
	u := s.DismissFindingWithUndo(a.Key())

	s.ReconcileDismissedContent([]alert.Finding{contentFinding("yara_match_scheduled", shaB)})

	if s.UndoDismiss(u) {
		t.Fatal("undo must not reach a dismissal that changed content ended")
	}
	if _, ok := s.EntryForKey(a.Key()); ok {
		t.Fatal("the revoked entry must stay gone")
	}
}
