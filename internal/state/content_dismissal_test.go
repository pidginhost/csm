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
	s := openTestStore(t)
	a := contentFinding("yara_match_scheduled", shaA)
	s.SetBaseline([]alert.Finding{a})

	s.ReconcileDismissedContent([]alert.Finding{contentFinding("yara_match_scheduled", "")})

	e, ok := s.EntryForKey(a.Key())
	if !ok || !e.IsBaseline || e.ContentSHA256 != shaA {
		t.Fatalf("entry = %+v, ok %v; an unknown hash must not revoke or overwrite", e, ok)
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

	if eligible, _ := s.BeginDelivery([]alert.Finding{b}); len(eligible) != 1 {
		t.Fatalf("changed content must be offered to email, got %d", len(eligible))
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
	s := openTestStore(t)
	a, b := contentFinding("yara_match_scheduled", shaA), contentFinding("yara_match_scheduled", shaB)
	s.SetBaseline([]alert.Finding{a})
	s.SetLatestFindings([]alert.Finding{a})
	resolve := s.PrepareFindingResolution(a)

	s.ReconcileDismissedContent([]alert.Finding{b})
	s.Update([]alert.Finding{b})
	s.SetLatestFindings([]alert.Finding{b})

	if resolve() {
		t.Fatal("a resolution started before the revocation must not clear the new detection")
	}
	e, ok := s.EntryForKey(b.Key())
	if !ok || e.IsBaseline {
		t.Fatalf("entry = %+v, ok %v; want an active entry", e, ok)
	}
}

func TestDismissedContentSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	a := contentFinding("yara_match_scheduled", shaA)
	s.SetBaseline([]alert.Finding{a})
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s, err = Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if e, _ := s.EntryForKey(a.Key()); e.ContentSHA256 != shaA {
		t.Fatalf("recorded content after reopen = %q, want A", e.ContentSHA256)
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
