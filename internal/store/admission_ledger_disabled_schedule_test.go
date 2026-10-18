package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// Disabled responses end without a reservation. Neither live scheduling
// nor challenge preview selection may wait for history or recovery space.
func TestAdmissionLedgerDisabledPicksNeedNoCapacity(t *testing.T) {
	for _, kind := range []admission.Kind{admission.KindBlockIP, admission.KindChallenge} {
		for _, preview := range []bool{false, true} {
			t.Run(kind.String()+"/"+map[bool]string{false: "live", true: "preview"}[preview], func(t *testing.T) {
				f := newLedgerFixture(t)
				f.begin()
				req := f.request("192.0.2.10", f.published(evidenceSpec{}))
				req.Kind = kind
				_, id := f.enqueue(req)
				f.leaveCeilingCredit(0, 0)
				f.adjustStorage(func(s *admission.StorageState) {
					s.General.Credit, s.Reserved.Credit = 0, 0
					leaveRecoveryRoom(s, 0)
				})
				before, storage, ceiling, notices := f.candidateOf(id), f.storageState(), f.ceilingState(), f.notices()
				if err := f.l.RefuseDisabled(func(admission.Candidate) bool { return false }); err != nil {
					t.Fatal(err)
				}
				c := f.candidateOf(id)
				if c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 || c.Transitions != before.Transitions+1 {
					t.Fatalf("disabled candidate = %+v", c)
				}
				selectFn := func() ([]admission.Pick, error) { return f.l.Schedule(fullSchedule, nil) }
				if preview {
					selectFn = func() ([]admission.Pick, error) { return f.l.SchedulePreview(nil) }
				}
				picks, err := selectFn()
				if err != nil || len(picks) != 0 {
					t.Fatalf("disabled work reached selection: %+v, %v", picks, err)
				}
				after := f.storageState()
				if after.General != storage.General || after.Reserved != storage.Reserved || after.Recovery != storage.Recovery || f.ceilingState() != ceiling || !reflect.DeepEqual(f.notices(), notices) {
					t.Fatal("refusal changed capacity or notices")
				}
			})
		}
	}
}

// Ending queued work cannot affect an unresolved attempt on the same target.
func TestAdmissionLedgerDisabledPickIgnoresRecoveryHold(t *testing.T) {
	f := newLedgerFixture(t)
	unknown, a := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	f.nextGeneration()
	id := f.queued()
	before, notices := f.candidateOf(id), f.notices()
	ceiling, unknownBefore := f.ceilingState(), f.candidateOf(unknown)
	if err := f.l.RefuseDisabled(func(c admission.Candidate) bool {
		if c.State != admission.StateQueued {
			t.Fatalf("policy consulted for %s", c.State)
		}
		return false
	}); err != nil {
		t.Fatal(err)
	}
	c := f.candidateOf(id)
	if c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Transitions != before.Transitions+1 {
		t.Fatalf("disabled candidate = %+v", c)
	}
	if !reflect.DeepEqual(f.notices(), notices) || !reflect.DeepEqual(f.candidateOf(unknown), unknownBefore) || f.ceilingState() != ceiling {
		t.Fatal("refusal changed notices, the unresolved attempt or its charge")
	}
	intents, err := f.l.UnresolvedIntents()
	if err != nil || len(intents) != 1 || intents[0].Action != a.Attempt.ID {
		t.Fatalf("refusal changed the recovery hold: %+v, %v", intents, err)
	}
}

// A failed refusal transaction changes nothing, and a retry counts each
// disabled response once while leaving allowed work byte-for-byte intact.
func TestAdmissionLedgerDisabledRefusalIsAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	ids := f.criticalArrivals("192.0.2.10", "192.0.2.11", "192.0.2.12")
	allowed := f.candidateOf(ids[2])
	allows := func(c admission.Candidate) bool { return c.Key.Target == allowed.Key.Target }
	before := f.snapshot()
	f.failNext("disabled")
	if err := f.l.RefuseDisabled(allows); err == nil || !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatalf("failed refusal changed the ledger: %v", err)
	}
	if err := f.l.RefuseDisabled(allows); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids[:2] {
		if c := f.candidateOf(id); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 {
			t.Fatalf("disabled candidate = %+v", c)
		}
	}
	if !reflect.DeepEqual(f.candidateOf(ids[2]), allowed) || f.schema() != admissionSchemaDisabled || f.countOf(admission.EventEnded, admission.ReasonDisabled, f.entryTier(ids[2])) != 2 {
		t.Fatal("refusal changed allowed work or recorded the wrong schema or count")
	}
	after := f.snapshot()
	if err := f.l.RefuseDisabled(allows); err != nil || !reflect.DeepEqual(f.snapshot(), after) {
		t.Fatalf("repeated refusal changed the ledger: %v", err)
	}
}

// Reserved work is past the opt-out check: refusal leaves it and still ends
// the queued work beside it.
func TestAdmissionLedgerDisabledLeavesReservedWork(t *testing.T) {
	f := newLedgerFixture(t)
	reserved, _ := f.admitted(time.Hour)
	f.nextGeneration()
	id := f.queued()
	before := f.candidateOf(reserved)
	if before.State != admission.StateReserved {
		t.Fatalf("fixture candidate is %s, want reserved", before.State)
	}
	if err := f.l.RefuseDisabled(func(admission.Candidate) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if got := f.candidateOf(reserved); !reflect.DeepEqual(got, before) {
		t.Fatalf("reserved candidate = %+v, want %+v", got, before)
	}
	if c := f.candidateOf(id); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled {
		t.Fatalf("queued candidate = %+v", c)
	}
}
