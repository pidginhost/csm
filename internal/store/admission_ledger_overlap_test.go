package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// An unresolved outcome holds every kind on its exact target, including
// work already queued; disjoint work proceeds without spending the held
// candidate's charge. Expiry alone does not release the hold.
func TestAdmissionLedgerUnknownTargetDefersOtherKinds(t *testing.T) {
	for _, queuedFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "later arrival", true: "already queued"}[queuedFirst], func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			block := f.arrive(f.arrival(evidenceSpec{cursor: "block"}))[0].Candidate
			other := f.arrival(evidenceSpec{cursor: "other"})
			other.Request.Kind = admission.KindPromote
			var queued admission.ArrivalResult
			if queuedFirst {
				queued = f.arrive(other)[0]
			}
			expires := f.wall.Add(time.Minute)
			_, a, granted, err := f.l.Reserve(block, admission.LaneGeneral, expires)
			if err != nil || !granted {
				t.Fatalf("reserve: %v %v", granted, err)
			}
			if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
				t.Fatal(err)
			}
			if !queuedFirst {
				queued = f.arrive(other)[0]
			}
			if queued.Err != nil || !queued.Created {
				t.Fatalf("other kind: %+v", queued)
			}
			free := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.11", cursor: "free"}))[0]
			if free.Err != nil || !free.Created {
				t.Fatalf("disjoint arrival: %+v", free)
			}
			before := f.snapshot()
			_, _, granted, err = f.l.Reserve(queued.Candidate, admission.LaneGeneral, f.wall.Add(time.Hour))
			wantLedgerReason(t, "held reservation", err, admission.ReasonPendingRecovery)
			if granted || !reflect.DeepEqual(f.snapshot(), before) {
				t.Fatal("a held reservation changed the ledger")
			}
			picks := f.schedule(fullSchedule)
			if len(picks) != 1 || picks[0].ID != free.Candidate {
				t.Fatalf("disjoint schedule: %+v", picks)
			}
			c := f.candidateOf(queued.Candidate)
			key := deferredKey(admission.ReasonPendingRecovery, f.entryTier(queued.Candidate))
			if c.State != admission.StateQueued || c.Reason != admission.ReasonPendingRecovery || c.Attempts != 0 || f.count(key) != 1 {
				t.Fatalf("held work: %+v, count %d", c, f.count(key))
			}
			f.schedule(fullSchedule)
			if got := f.candidateOf(queued.Candidate); got.Transitions != c.Transitions || f.count(key) != 1 {
				t.Fatalf("repeated hold: %+v, count %d", got, f.count(key))
			}
			_, disjoint, granted, err := f.l.Reserve(free.Candidate, picks[0].Lane, f.wall.Add(time.Hour))
			if err != nil || !granted {
				t.Fatalf("disjoint reserve: %v %v", granted, err)
			}
			if _, _, _, err = f.l.Execute(disjoint.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			if _, _, err = f.l.Finish(disjoint.Attempt.ID, admission.DispositionApplied); err != nil {
				t.Fatal(err)
			}
			f.ackAll()
			if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatal(err)
			}
			f.tickAt(expires)
			if picks = f.schedule(fullSchedule); len(picks) != 0 {
				t.Fatalf("expired but unresolved: %+v", picks)
			}
			if wake, ok, wakeErr := f.l.NextWake(); wakeErr != nil || !ok || !wake.After(f.wall) {
				t.Fatalf("held wake: %v %v %v", wake, ok, wakeErr)
			}
			if _, _, granted, err = f.l.RetireUnproven(a.Attempt.ID); err != nil || !granted {
				t.Fatalf("retire: %v %v", granted, err)
			}
			if picks = f.schedule(fullSchedule); len(picks) != 1 || picks[0].ID != queued.Candidate || f.candidateOf(queued.Candidate).Reason != 0 {
				t.Fatalf("released schedule: %+v", picks)
			}
			if _, _, granted, err = f.l.Reserve(queued.Candidate, picks[0].Lane, f.wall.Add(time.Hour)); err != nil || !granted {
				t.Fatalf("released reservation: %v %v", granted, err)
			}
		})
	}
}

// An intent that becomes unknown after another kind reserved must stop
// that reserved attempt before dispatch. One overlapping member refuses
// the whole batch, including a disjoint member processed first.
func TestAdmissionLedgerUnknownTargetRefusesReservedBatch(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	block := f.arrive(f.arrival(evidenceSpec{cursor: "block"}))[0].Candidate
	other := f.arrival(evidenceSpec{cursor: "other"})
	other.Request.Kind = admission.KindPromote
	queued := f.arrive(other)[0]
	if queued.Err != nil {
		t.Fatal(queued.Err)
	}
	_, held, granted, err := f.l.Reserve(queued.Candidate, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil || !granted {
		t.Fatalf("reserve other: %v %v", granted, err)
	}
	free := f.reservedAt("192.0.2.11", f.wall.Add(time.Hour))
	expires := f.wall.Add(time.Minute)
	_, a, granted, err := f.l.Reserve(block, admission.LaneGeneral, expires)
	if err != nil || !granted {
		t.Fatalf("reserve block: %v %v", granted, err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	intents, granted, err := f.l.ExecuteBatch([]admission.ActionID{free.Attempt.ID, held.Attempt.ID})
	wantLedgerReason(t, "overlapping batch", err, admission.ReasonPendingRecovery)
	if intents != nil || granted || !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a refused overlapping batch changed the ledger")
	}
	f.ackAll()
	f.tickAt(expires)
	if _, _, granted, err = f.l.RetireUnproven(a.Attempt.ID); err != nil || !granted {
		t.Fatalf("retire: %v %v", granted, err)
	}
	intents, granted, err = f.l.ExecuteBatch([]admission.ActionID{free.Attempt.ID, held.Attempt.ID})
	if err != nil || !granted || len(intents) != 2 || intents[1].Action != held.Attempt.ID || !intents[1].ExpiresAt.Equal(held.ExpiresAt) {
		t.Fatalf("released batch: %+v %v %v", intents, granted, err)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}
