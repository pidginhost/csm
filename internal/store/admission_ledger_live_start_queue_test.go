package store

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// Legacy blocking answered every block_ip finding while admission
// previewed, so the live start ends the block_ip work the preview period
// left queued, deferred or not, silently and without a charge: none of it
// runs under the live policy. Queued work of other kinds stays.
func TestAdmissionLedgerLiveStartEndsQueuedPreviewBlocks(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	block := f.published(evidenceSpec{target: "192.0.2.41", cursor: "offset=41"})
	challenge := f.published(evidenceSpec{target: "192.0.2.42", cursor: "offset=42"})
	_, blockID := f.enqueue(f.request("192.0.2.41", block))
	_, waitingID := f.enqueue(f.request("192.0.2.43", f.published(evidenceSpec{target: "192.0.2.43", cursor: "offset=43"})))
	if _, err := f.l.Defer(waitingID, admission.ReasonSetFull); err != nil {
		t.Fatal(err)
	}
	req := f.request("192.0.2.42", challenge)
	req.Kind = admission.KindChallenge
	_, challengeID := f.enqueue(req)
	before, notices, ceiling := f.candidateOf(blockID), f.notices(), f.ceilingState()
	kept := f.candidateOf(challengeID)
	if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
		t.Fatal(err)
	}
	c := f.candidateOf(blockID)
	if c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 || c.Transitions != before.Transitions+1 {
		t.Fatalf("preview-period block after the live start = %+v", c)
	}
	if c = f.candidateOf(waitingID); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 {
		t.Fatalf("deferred preview-period block after the live start = %+v", c)
	}
	if !reflect.DeepEqual(f.candidateOf(challengeID), kept) {
		t.Fatalf("the live start changed a queued challenge: %+v", f.candidateOf(challengeID))
	}
	if !reflect.DeepEqual(f.notices(), notices) || f.ceilingState() != ceiling {
		t.Fatal("ending preview-period work raised a notice or spent capacity")
	}
}

// rowsOf are the stored rows of one bucket.
func rowsOf(snap map[string]string, bucket string) map[string]string {
	out := map[string]string{}
	for k, v := range snap {
		if strings.HasPrefix(k, bucket+":") {
			out[k] = v
		}
	}
	return out
}

// endedAs counts the queued candidates that ended for reason.
func (f *ledgerFixture) endedAs(reason admission.Reason) uint64 {
	f.t.Helper()
	var n uint64
	for _, row := range f.countersSnapshot() {
		if row.Key.Event == admission.EventEnded && row.Key.Reason == reason {
			n += row.N
		}
	}
	return n
}

// A block waiting for a retry ends at the live start as any queued block
// does, in its backoff or past it: refused as disabled, once. What it
// already spent stays spent: its failed attempt, the charge and the
// expiry are kept, and its paid history ends. Nothing new is charged or
// announced, the ledger still opens, and a second live start conflicts
// without ending anything again.
func TestAdmissionLedgerLiveStartKeepsPriorAttempts(t *testing.T) {
	for _, tc := range []struct {
		name string
		wait time.Duration
	}{
		{"inside the backoff", 0},
		{"after the backoff", admission.RetryBackoff(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedgerFixture(t)
			id, a := f.admitted(time.Hour)
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
				t.Fatal(err)
			}
			f.tickAt(f.wall.Add(tc.wait))
			before := f.candidateOf(id)
			if before.State != admission.StateQueued || before.Attempts != 1 || before.NotBefore.IsZero() {
				t.Fatalf("fixture is not a queued retry: %+v", before)
			}
			paid, found := f.historyOf(id)
			if !found || paid.General+paid.Reserved == 0 || !paid.Ended.IsZero() {
				t.Fatalf("fixture retry has no live paid history: %+v (%v)", paid, found)
			}
			snap, notices, disabled := f.snapshot(), f.notices(), f.endedAs(admission.ReasonDisabled)
			var published []admission.Candidate
			f.l.ObserveRefusals(func(c admission.Candidate, _ error, _ time.Time) { published = append(published, c) })
			if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
				t.Fatal(err)
			}
			c := f.candidateOf(id)
			if c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 1 ||
				!c.ExpiresAt.Equal(before.ExpiresAt) || c.Transitions != before.Transitions+1 {
				t.Fatalf("retry after the live start = %+v, was %+v", c, before)
			}
			after := f.snapshot()
			if !reflect.DeepEqual(rowsOf(after, admissionAttemptsBucket), rowsOf(snap, admissionAttemptsBucket)) {
				t.Fatal("the live start changed an attempt record")
			}
			if n := f.endedAs(admission.ReasonDisabled); n != disabled+1 || len(published) != 1 || published[0].Key != c.Key {
				t.Fatalf("disabled endings %d -> %d, published %d; want one", disabled, n, len(published))
			}
			if !reflect.DeepEqual(f.notices(), notices) {
				t.Fatal("ending a retry raised a notice")
			}
			ended, found := f.historyOf(id)
			if !found || ended.General != paid.General || ended.Reserved != paid.Reserved || ended.Ended.IsZero() || ended.Eligible.IsZero() {
				t.Fatalf("history after the live start = %+v (%v), paid %+v", ended, found, paid)
			}
			charges := f.charges()
			if len(charges) != 1 || charges[0].Cost != 1 {
				t.Fatalf("charges after the live start = %+v, want the retry's one charge", charges)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("reopening after the live start: %v", err)
			}
			if err := f.l.StartLive(admission.LegacyHandover{}); !errors.Is(err, admission.ErrTransitionConflict) {
				t.Fatalf("second live start = %v, want a conflict", err)
			}
			if !reflect.DeepEqual(f.snapshot(), after) || len(published) != 1 {
				t.Fatal("a second live start changed the ledger or reported another refusal")
			}
		})
	}
}
