package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// observedArrival queues one arrival at target and previews it on the
// general lane.
func (f *ledgerFixture) observedArrival(target, cursor string) (admission.CandidateID, admission.AttemptRecord) {
	f.t.Helper()
	res := f.arrive(f.arrival(evidenceSpec{target: target, cursor: cursor}))[0]
	if res.Err != nil || !res.Created {
		f.t.Fatalf("arrival = %+v", res)
	}
	_, a, granted, err := f.l.Observe(res.Candidate, admission.LaneGeneral, f.wall.Add(24*time.Hour))
	if err != nil || !granted {
		f.t.Fatalf("observe: granted %v, %v", granted, err)
	}
	return res.Candidate, a
}

func outcomeCount(s admission.LedgerStatus, d admission.Disposition) uint64 {
	var n uint64
	for _, row := range s.Outcomes.Hour {
		if row.Outcome == d.String() {
			n += row.N
		}
	}
	return n
}

// An observe preview reserves its attempt as live work would, charge
// included, and ends it in the same transaction without running it:
// candidate and attempt end observed, the outcome counts as observe, the
// unused execution slot returns, nothing is noticed, the episode keeps its
// quiet-hour end and the history stays for the ordinary review window. A
// reopened ledger proves the result.
func TestAdmissionLedgerObserveEndsAReservedAttempt(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	base := f.storageState().AuditSlots
	charges := len(f.charges())
	notices, err := f.l.PendingNotices()
	if err != nil {
		t.Fatal(err)
	}
	id := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
	c, a, granted, err := f.l.Observe(id, admission.LaneGeneral, f.wall.Add(24*time.Hour))
	if err != nil || !granted {
		t.Fatalf("observe: granted %v, %v", granted, err)
	}
	if c.State != admission.StateObserved || c.Disposition != admission.DispositionObserve || c.Transitions != 3 || c.Attempts != 1 {
		t.Fatalf("candidate = %s/%s after %d transitions and %d attempts", c.State, c.Disposition, c.Transitions, c.Attempts)
	}
	if a.State != admission.StateObserved || a.Disposition != admission.DispositionObserve || !a.Finished.Equal(f.wall) || !a.Reserved.Equal(f.wall) {
		t.Fatalf("attempt = %+v", a)
	}
	if stored, loadErr := f.l.Candidate(id); loadErr != nil || !reflect.DeepEqual(stored, c) {
		t.Fatalf("stored candidate = %+v, %v", stored, loadErr)
	}
	if got := len(f.charges()); got != charges+1 {
		t.Fatalf("charges = %d, want %d", got, charges+1)
	}
	var states []admission.State
	for _, row := range f.pendingAudit() {
		states = append(states, row.State)
	}
	if !reflect.DeepEqual(states, []admission.State{admission.StateReserved, admission.StateObserved}) {
		t.Fatalf("audit rows = %v", states)
	}
	if got := f.storageState().AuditSlots; got != base+2 {
		t.Fatalf("audit slots = %d, want %d", got, base+2)
	}
	if got := outcomeCount(f.l.Status(), admission.DispositionObserve); got != 1 {
		t.Fatalf("observe outcomes = %d, want 1", got)
	}
	after, err := f.l.PendingNotices()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, notices) {
		t.Fatalf("an observe preview raised a notice: %+v", after)
	}
	if row, found := f.episodeAt("192.0.2.10"); !found || !row.Verified.IsZero() {
		t.Fatalf("episode = %+v (found %v), want no verified end", row, found)
	}
	if h, found := f.historyEntry(id); !found || !h.Eligible.Equal(f.wall.Add(admission.HistoryRetention)) {
		t.Fatalf("history = %+v (found %v)", h, found)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopening an observed candidate: %v", err)
	}
}

// An observed line answers later observations of its episode as an existing
// effect, as a verified one would; the episode ends an hour after its last
// accepted observation, since a preview sets no verified end.
func TestAdmissionLedgerObservedLineAnswersUntilTheQuietHour(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first, _ := f.observedArrival("192.0.2.10", "offset=1")
	f.tickAt(f.wall.Add(30 * time.Minute))
	wantLedgerReason(t, "inside the quiet hour", f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0].Err, admission.ReasonExistingEffect)
	f.tickAt(f.wall.Add(time.Hour))
	next := f.arrive(f.arrival(evidenceSpec{cursor: "offset=3"}))[0]
	if next.Err != nil || !next.Created || f.candidateOf(next.Candidate).Key.Episode == f.candidateOf(first).Key.Episode {
		t.Fatalf("after the quiet hour = %+v", next)
	}
}

// A preview refuses as a reservation does and then changes nothing: an
// exhausted ceiling defers it, an ended candidate cannot be previewed, and
// a failed transaction leaves no reserved attempt behind.
func TestAdmissionLedgerObserveRefusesAsAReservation(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	id := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
	before := f.snapshot()
	f.failNext("observe")
	if _, _, _, err := f.l.Observe(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err == nil {
		t.Fatal("an injected failure committed")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed preview changed the ledger")
	}
	_, _, _, err := f.l.Observe(id, admission.LaneGeneral, f.wall)
	wantLedgerReason(t, "expiry now", err, admission.ReasonInvalid)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused preview changed the ledger")
	}
	if _, _, _, err = f.l.Observe(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = f.l.Observe(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerErr(t, "a second preview", err, admission.ErrCandidateTerminal)
}

// A reservation that already exists is read back, never ended as a
// preview: it may be live work that is running.
func TestAdmissionLedgerObserveReadsBackAReservation(t *testing.T) {
	f := newLedgerFixture(t)
	id, reserved := f.admitted(time.Hour)
	before := f.snapshot()
	c, a, granted, err := f.l.Observe(id, 0, time.Time{})
	if err != nil || granted || a != reserved || c.State != admission.StateReserved {
		t.Fatalf("readback = %s, %+v, granted %v, %v", c.State, a, granted, err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a readback changed the ledger")
	}
}

// Only Observe records a preview: an attempt handed to Finish was
// dispatched, so its outcome is applied, failed or unknown.
func TestAdmissionLedgerFinishRefusesAPreview(t *testing.T) {
	f := newLedgerFixture(t)
	_, a := f.admitted(time.Hour)
	before := f.snapshot()
	for _, d := range []admission.Disposition{admission.DispositionObserve, admission.DispositionDryRun} {
		_, _, err := f.l.Finish(a.Attempt.ID, d)
		wantLedgerReason(t, d.String(), err, admission.ReasonInvalid)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused outcome changed the ledger")
	}
}
