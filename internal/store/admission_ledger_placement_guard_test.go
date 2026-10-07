package store

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// strayNextGeneration stores a candidate at the generation the target's
// episode would open next, as only damage leaves it: placement then lands
// on a candidate it did not choose.
func (f *ledgerFixture) strayNextGeneration(cursor string) admission.CandidateID {
	f.t.Helper()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0]
	if _, err := f.l.Terminate(first.Candidate, admission.ReasonPolicy); err != nil {
		f.t.Fatal(err)
	}
	row, _ := f.episodeAt("192.0.2.10")
	req := f.request("192.0.2.10", f.published(evidenceSpec{cursor: cursor}))
	req.Episode, req.Generation = row.ID, 2
	_, stray := f.enqueue(req)
	return stray
}

// R12: an arrival that lands on an ended or in-flight candidate is a
// counted refusal, never dropped uncounted. Placement never chooses one,
// so the count reads as invalid.
func TestAdmissionLedgerCountsAPlacementOnAnEndedOrBusyCandidate(t *testing.T) {
	for name, tc := range map[string]struct {
		settle func(f *ledgerFixture, id admission.CandidateID)
		want   error
	}{
		"ended": {func(f *ledgerFixture, id admission.CandidateID) {
			if _, err := f.l.Terminate(id, admission.ReasonPolicy); err != nil {
				f.t.Fatal(err)
			}
		}, admission.ErrCandidateTerminal},
		"in flight": {func(f *ledgerFixture, id admission.CandidateID) {
			if _, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
				f.t.Fatal(err)
			}
		}, admission.ErrTransitionConflict},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			stray := f.strayNextGeneration("offset=2")
			tc.settle(f, stray)
			before := f.refusals(admission.ReasonInvalid)
			f.tickAt(f.wall.Add(time.Second))
			out := f.arrive(f.arrival(evidenceSpec{cursor: "offset=3"}))
			if len(out) != 1 || !errors.Is(out[0].Err, tc.want) {
				t.Fatalf("result = %+v", out)
			}
			if got := f.refusals(admission.ReasonInvalid); got != before+1 {
				t.Fatalf("invalid refusals = %d, want %d", got, before+1)
			}
		})
	}
}

// R12 (M1): a row placement chose but cannot store is damage, not a
// refused arrival that would commit a candidate without its row.
func TestEpisodeRowThatCannotBeStoredIsDamage(t *testing.T) {
	f := newLedgerFixture(t)
	err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putEpisode(tx, "ip:192.0.2.10", admission.Episode{}) })
	if !isCorrupt(err) {
		t.Fatalf("err = %v", err)
	}
	if _, refused := admission.ReasonOf(err); refused {
		t.Fatalf("a row that cannot be stored reads as a refusal: %v", err)
	}
}
