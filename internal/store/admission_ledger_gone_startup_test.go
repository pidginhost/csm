package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// Startup treats a gone block like an evicted one: nothing it applied
// remains, so its firewall row is marked unverified before the restore
// and then removed. A restart cannot bring back an element whose slot the
// ledger no longer counts; a held block keeps its row.
func TestAdmissionLedgerStartupSettlesGoneBlocks(t *testing.T) {
	f := liveLedgerFixture(t)
	gone := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	held := f.verifiedWith("192.0.2.11", admission.SeverityWarning, time.Hour)
	asked, err := f.l.HeldEffects(10)
	if err != nil || len(asked) != 2 {
		t.Fatalf("held %+v %v", asked, err)
	}
	// Both share an expiry, so the list orders them by action.
	answer := make([]bool, len(asked))
	for i, h := range asked {
		answer[i] = h.Action != gone.Attempt.ID
	}
	f.observeHeld(asked, answer...)
	ids := []string{string(gone.Attempt.ID), string(held.Attempt.ID)}
	readers := map[string]func(*DB, []string) ([]string, error){"settled": ReadSettledBlockActions, "unproven": ReadUnprovenBlockActions}
	for name, read := range readers {
		if got, readErr := read(f.db, ids); readErr != nil || len(got) != 0 {
			t.Errorf("%s after one miss: %v %v, want none", name, got, readErr)
		}
	}
	f.observeHeld(asked, answer...)
	for name, read := range readers {
		if got, readErr := read(f.db, ids); readErr != nil || !reflect.DeepEqual(got, []string{string(gone.Attempt.ID)}) {
			t.Errorf("%s: %v %v, want the gone block only", name, got, readErr)
		}
	}
}
