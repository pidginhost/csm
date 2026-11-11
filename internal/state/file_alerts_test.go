package state

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

const removedPath = "/home/alice/public_html/wp-includes/index.php"

func newKeys(findings []alert.Finding) map[string]bool {
	keys := map[string]bool{}
	for _, f := range findings {
		keys[f.Key()] = true
	}
	return keys
}

// After CSM removes a file, every alert about it must be able to fire again:
// a loop that writes the file back produces the same findings, which the 24h
// repeat window would otherwise hide.
func TestForgetFileAlertsClearsEveryFindingAboutThePath(t *testing.T) {
	s := openTestStore(t)
	dismissed := alert.Finding{Check: "webshell", Message: "dismissed", FilePath: removedPath}
	s.SetBaseline([]alert.Finding{dismissed})
	realtime := alert.Finding{Check: "signature_match_realtime", Message: "realtime", FilePath: removedPath}
	scanned := alert.Finding{Check: "obfuscated_php", Message: "scanned", FilePath: "/home/alice/public_html/wp-includes/./index.php"}
	other := alert.Finding{Check: "obfuscated_php", Message: "other file", FilePath: "/home/alice/public_html/other.php"}
	noPath := alert.Finding{Check: "webshell", Message: "no path"}
	all := []alert.Finding{realtime, scanned, other, noPath, dismissed}
	internal := alert.Finding{Check: "_internal", Message: "sentinel", FilePath: removedPath}
	s.Update([]alert.Finding{realtime, scanned, other, noPath, dismissed, internal})
	if got := s.FilterNew(all); len(got) != 0 {
		t.Fatalf("setup: findings already new before the removal: %v", newKeys(got))
	}

	s.ForgetFileAlerts(removedPath)

	got := newKeys(s.FilterNew(all))
	if len(got) != 2 || !got[realtime.Key()] || !got[scanned.Key()] {
		t.Fatalf("new after removal = %v, want only the two findings about %s", got, removedPath)
	}
	if entry, ok := s.EntryForKey(dismissed.Key()); !ok || !entry.IsBaseline {
		t.Fatalf("dismissal forgotten: %+v ok=%t", entry, ok)
	}
	if entry, ok := s.EntryForKey(internal.Key()); !ok || entry.Path != removedPath {
		t.Fatalf("internal entry forgotten: %+v ok=%t", entry, ok)
	}
}

// Delivery creates entries before Update, including for action findings that
// never reach Update. A removal must clear them and invalidate old receipts.
func TestForgetFileAlertsClearsDeliveryEntries(t *testing.T) {
	for _, completed := range []bool{false, true} {
		s := openTestStore(t)
		f := alert.Finding{Check: "webshell", Message: "delivered", FilePath: "/home/alice/public_html/wp-includes/./index.php"}
		batch := []alert.Finding{f}
		selected, finish := s.BeginDelivery(batch)
		if len(selected) != 1 {
			t.Fatal("setup: first delivery was not selected")
		}
		if completed {
			finish(selected)
		}

		s.ForgetFileAlerts(removedPath)

		if entry, ok := s.EntryForKey(f.Key()); ok {
			t.Fatalf("completed=%t: delivery entry survived removal: %+v", completed, entry)
		}
		returned, finishReturn := s.BeginDelivery(batch)
		if len(returned) != 1 {
			t.Fatal("return of removed file was not offered for delivery")
		}
		if !completed {
			finish(selected)
			if entry, _ := s.EntryForKey(f.Key()); entry.Emailed != "" {
				t.Fatal("old delivery muted the returned file")
			}
		}
		finishReturn(returned)
		if got := offered(s, batch...); len(got) != 0 {
			t.Fatal("return's delivery receipt was lost")
		}
	}
}

// The path must survive a restart, or alert state written before it cannot be
// cleared afterwards.
func TestForgetFileAlertsAfterReload(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := alert.Finding{Check: "obfuscated_php", Message: "scanned", FilePath: removedPath}
	s.Update([]alert.Finding{f})
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if got := reopened.FilterNew([]alert.Finding{f}); len(got) != 0 {
		t.Fatal("setup: alert state not persisted")
	}

	reopened.ForgetFileAlerts(removedPath)

	if got := reopened.FilterNew([]alert.Finding{f}); len(got) != 1 {
		t.Fatal("reloaded alert state about the removed file was kept")
	}
}

func TestForgetFileAlertsIgnoresEmptyPath(t *testing.T) {
	s := openTestStore(t)
	noPath := alert.Finding{Check: "webshell", Message: "no path"}
	s.Update([]alert.Finding{noPath})

	s.ForgetFileAlerts("")

	if got := s.FilterNew([]alert.Finding{noPath}); len(got) != 0 {
		t.Fatal("an empty path cleared findings that name no file")
	}
}
