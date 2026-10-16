package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

func pendingSet(ids ...admission.CandidateID) map[admission.CandidateID]admission.Answer {
	out := map[admission.CandidateID]admission.Answer{}
	for _, id := range ids {
		out[id] = admission.AnswerPending
	}
	return out
}

// A panel allow ends its candidate without a charge, so a schedule selects
// it as uncharged work with the live ceiling and history spent: it costs
// nothing, takes no deferral and wakes the owner now. Charged work still
// waits for budget, and nothing is charged.
func TestAdmissionLedgerScheduleSelectsAllowsUncharged(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	ids := f.criticalArrivals("192.0.2.10", "192.0.2.11")
	f.leaveCeilingCredit(0, 0)
	f.adjustStorage(func(s *admission.StorageState) { s.General.Credit, s.Reserved.Credit = 0, 0 })
	allowed := map[admission.CandidateID]admission.Answer{ids[0]: admission.AnswerAllow}
	ceiling, storage := f.ceilingState(), f.storageState()
	if wake, ok, err := f.l.NextWake(allowed); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("wake with an allow = %v %v %v, want now", wake, ok, err)
	}
	picks, err := f.l.Schedule(fullSchedule, allowed)
	if err != nil || len(picks) != 1 || picks[0].ID != ids[0] || picks[0].Cost != 0 || picks[0].Bytes != 0 {
		t.Fatalf("picks = %+v, %v", picks, err)
	}
	if c := f.candidateOf(ids[0]); c.State != admission.StateQueued || c.Reason != 0 {
		t.Fatalf("allowed pick = %+v", c)
	}
	if c := f.candidateOf(ids[1]); c.Reason != admission.ReasonCeiling {
		t.Fatalf("charged work = %+v, want a ceiling deferral", c)
	}
	// The charged pick's deferral records its notice; nothing is charged.
	if after := f.storageState(); !reflect.DeepEqual(f.ceilingState(), ceiling) || after.General != storage.General || after.Reserved != storage.Reserved || after.Recovery != storage.Recovery {
		t.Fatal("selecting an allow charged capacity")
	}
}

// A candidate waiting on the panel's verdict is never picked, so it cannot
// keep taking the bounded members of a schedule, and its scope keeps its
// turn: once the answer arrives it competes as before. Another scope's
// ready work is served meanwhile.
func TestAdmissionLedgerSchedulePassesOverPendingWork(t *testing.T) {
	f := newLedgerFixture(t)
	a := f.fill(1, evidenceSpec{owner: f.owner("alice")})
	b := f.fill(2, evidenceSpec{owner: f.owner("bob")})
	pending := pendingSet(a[0])
	for range 2 {
		picks, err := f.l.Schedule(oneEach, pending)
		if err != nil || len(picks) != 1 || f.scopeOf(picks[0].ID) != f.scopeOf(b[0]) {
			t.Fatalf("schedule with alice pending = %+v, %v", picks, err)
		}
		if _, _, _, err = f.l.Reserve(picks[0].ID, picks[0].Lane, f.wall.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if picks, err := f.l.Schedule(oneEach, pending); err != nil || len(picks) != 0 {
		t.Fatalf("only pending work is left: %+v, %v", picks, err)
	}
	if picks, err := f.l.Schedule(oneEach, nil); err != nil || len(picks) != 1 || picks[0].ID != a[0] {
		t.Fatalf("the answered candidate = %+v, %v", picks, err)
	}
}

// Without live budget, pending work takes no ceiling or storage deferral,
// raises no notice and makes no transition; other ready work is deferred
// as before.
func TestAdmissionLedgerScheduleDefersNoPendingWork(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	ids := f.criticalArrivals("192.0.2.10", "192.0.2.11")
	f.leaveCeilingCredit(0, 0)
	waiting := f.candidateOf(ids[0])
	picks, err := f.l.Schedule(fullSchedule, pendingSet(ids[0]))
	if err != nil || len(picks) != 0 {
		t.Fatalf("picks without budget = %+v, %v", picks, err)
	}
	if c := f.candidateOf(ids[0]); c.Reason != 0 || c.Transitions != waiting.Transitions {
		t.Fatalf("pending work was deferred: %+v", c)
	}
	if c := f.candidateOf(ids[1]); c.Reason != admission.ReasonCeiling {
		t.Fatalf("ready work = %+v, want a ceiling deferral", c)
	}
	if n := f.count(deferredKey(admission.ReasonCeiling, critC2)); n != 1 {
		t.Fatalf("deferrals counted = %d", n)
	}
}

// Pending work alone needs no wake: its answer, not the ledger, brings the
// next turn. Its age-out still does, and other ready work wakes at once.
func TestAdmissionLedgerNextWakeSkipsPendingWork(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	wake, ok, err := f.l.NextWake(pendingSet(id))
	if err != nil || !ok || !wake.Equal(f.candidateOf(id).AgeOut) {
		t.Fatalf("pending wake = %v %v %v, want its age-out", wake, ok, err)
	}
	if wake, ok, err = f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("ready wake = %v %v %v, want now", wake, ok, err)
	}
}

// A pending retry needs no wake at its backoff end either: only its
// deadline, here the expiry of its first attempt.
func TestAdmissionLedgerNextWakeSkipsPendingRetries(t *testing.T) {
	f := newLedgerFixture(t)
	id, a := f.admitted(time.Minute)
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	c := f.candidateOf(id)
	wake, ok, err := f.l.NextWake(pendingSet(id))
	if err != nil || !ok || !wake.Equal(c.ExpiresAt) {
		t.Fatalf("pending retry wake = %v %v %v, want its expiry %v, not its backoff end %v", wake, ok, err, c.ExpiresAt, c.NotBefore)
	}
}

// An allow behind charged work in its own scope is still served with the
// budgets spent: the scope's head waits for budget and would hold the
// allow behind it, so the schedule adds the allows its lanes left.
func TestAdmissionLedgerScheduleServesAllowsBehindChargedWork(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	ids := f.criticalArrivals("192.0.2.10", "192.0.2.11")
	// Queued together, the lower ID is the scope's head.
	head, behind := ids[0], ids[1]
	if behind < head {
		head, behind = behind, head
	}
	if f.scopeOf(head) != f.scopeOf(behind) || !f.candidateOf(head).FirstQueued.Equal(f.candidateOf(behind).FirstQueued) {
		t.Fatal("fixture: the candidates do not share a scope and queue time")
	}
	f.leaveCeilingCredit(0, 0)
	allowed := map[admission.CandidateID]admission.Answer{behind: admission.AnswerAllow}
	if wake, ok, err := f.l.NextWake(allowed); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("wake with an allow behind charged work = %v %v %v, want now", wake, ok, err)
	}
	picks, err := f.l.Schedule(fullSchedule, allowed)
	if err != nil || len(picks) != 1 || picks[0].ID != behind || picks[0].Cost != 0 || picks[0].Bytes != 0 {
		t.Fatalf("picks = %+v, %v", picks, err)
	}
	if c := f.candidateOf(head); c.Reason != admission.ReasonCeiling {
		t.Fatalf("charged head = %+v, want a ceiling deferral", c)
	}
	both := map[admission.CandidateID]admission.Answer{head: admission.AnswerAllow, behind: admission.AnswerAllow}
	if picks, err = f.l.Schedule(admission.ScheduleLimits{Members: 1}, both); err != nil || len(picks) != 1 || picks[0].ID != head {
		t.Fatalf("allows past the member bound = %+v, %v", picks, err)
	}
}
