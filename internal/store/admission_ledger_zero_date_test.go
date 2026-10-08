package store

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// Zero is an incarnation token, not an absent token or a zero generation.
// A restart and an unchanged observation preserve queued work; a changed
// date or an observed deletion retires it.
func TestAdmissionLedgerZeroCreationDateLifecycle(t *testing.T) {
	for _, change := range []string{"new creation date", "observed deletion"} {
		t.Run(change, func(t *testing.T) {
			f := newLedgerFixture(t)
			obs := admission.InventoryObservation{
				Accounts:     []string{"system"},
				Incarnations: map[string]string{"system": "startdate:0"},
			}
			if err := f.l.RefreshInventory(obs); err != nil {
				t.Fatal(err)
			}
			owner := f.owner("system")
			if owner.Generation() == 0 {
				t.Fatal("a zero creation date produced a zero generation")
			}
			root := f.published(evidenceSpec{owner: owner, cursor: "queued"})
			_, queued := f.enqueue(f.request("192.0.2.10", root))
			reopened, err := OpenAdmissionLedger(f.db, f.reg)
			if err != nil {
				t.Fatal(err)
			}
			f.l = reopened
			f.tickAt(f.wall.Add(time.Minute))
			if err := f.l.RefreshInventory(obs); err != nil {
				t.Fatal(err)
			}
			if got := f.owner("system"); got != owner {
				t.Fatalf("unchanged zero date after reopening changed owner: %v, want %v", got, owner)
			}
			if got, err := f.l.Candidate(queued); err != nil || got.State != admission.StateQueued {
				t.Fatalf("unchanged zero date retired queued work: %+v, %v", got, err)
			}
			switch change {
			case "new creation date":
				obs.Incarnations["system"] = "startdate:1"
			case "observed deletion":
				if err := f.l.RefreshInventory(admission.InventoryObservation{}); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.l.RefreshInventory(obs); err != nil {
				t.Fatal(err)
			}
			if got := f.owner("system"); got.Generation() <= owner.Generation() {
				t.Fatalf("%s kept the old generation: %v, was %v", change, got, owner)
			}
			if got, err := f.l.Candidate(queued); err != nil || got.State != admission.StateRefused || got.Reason != admission.ReasonStaleIdentity {
				t.Fatalf("%s kept stale queued work: %+v, %v", change, got, err)
			}
		})
	}
}
