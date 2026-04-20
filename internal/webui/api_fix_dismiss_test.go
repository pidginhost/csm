package webui

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// TestAPIFixDismissKeyFallback documents why apiFix must use the client-
// supplied canonical key (matching alert.Finding.Key()) when dismissing
// after a successful fix. A finding with non-empty Details has a key of
// the form "check:message:<hash4>"; using "check:message" alone silently
// fails to remove it from the latest set, so the finding reappears on
// the next render.
func TestAPIFixDismissKeyFallback(t *testing.T) {
	f := alert.Finding{
		Check:   "world_writable_php",
		Message: "World-writable PHP file: /home/u/foo.php",
		Details: "Mode: -rw-rw-rw-",
	}
	canonicalKey := f.Key()
	legacyKey := f.Check + ":" + f.Message
	if canonicalKey == legacyKey {
		t.Fatalf("expected canonical key %q to differ from legacy %q", canonicalKey, legacyKey)
	}

	s := newTestServer(t, "tok")

	// Legacy "check:message" key must not match when Details is set.
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})
	s.store.DismissLatestFinding(legacyKey)
	if got := len(s.store.LatestFindings()); got != 1 {
		t.Errorf("legacy key removed finding unexpectedly (got %d, want 1) — pre-fix bug scenario", got)
	}

	// Canonical key (what the enriched API hands to the client) must match.
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})
	s.store.DismissLatestFinding(canonicalKey)
	if got := len(s.store.LatestFindings()); got != 0 {
		t.Errorf("canonical key failed to remove finding (got %d, want 0)", got)
	}
}
