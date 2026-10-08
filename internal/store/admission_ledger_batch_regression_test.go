package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// A running member belongs to a different batch from a newly reserved
// member. Their target overlap must not hide that conflict behind a
// recovery deferral or make the refusal depend on member order.
func TestAdmissionLedgerExecuteRejectsOverlappingMixedBatch(t *testing.T) {
	for _, runningFirst := range []bool{false, true} {
		name := "reserved first"
		if runningFirst {
			name = "running first"
		}
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			block := f.arrive(f.arrival(evidenceSpec{cursor: "block"}))[0]
			other := f.arrival(evidenceSpec{cursor: "other"})
			other.Request.Kind = admission.KindPromote
			promote := f.arrive(other)[0]
			if block.Err != nil || promote.Err != nil {
				t.Fatalf("arrivals: %+v %+v", block, promote)
			}
			reserve := func(id admission.CandidateID) admission.AttemptRecord {
				t.Helper()
				_, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
				if err != nil || !granted {
					t.Fatalf("reserve: %v %v", granted, err)
				}
				return a
			}
			running, reserved := reserve(block.Candidate), reserve(promote.Candidate)
			if _, _, granted, err := f.l.Execute(running.Attempt.ID); err != nil || !granted {
				t.Fatalf("execute block: %v %v", granted, err)
			}
			ids := []admission.ActionID{reserved.Attempt.ID, running.Attempt.ID}
			if runningFirst {
				ids[0], ids[1] = ids[1], ids[0]
			}
			before := f.snapshot()
			intents, granted, err := f.l.ExecuteBatch(ids)
			wantLedgerErr(t, "mixed batch", err, admission.ErrTransitionConflict)
			if granted || intents != nil {
				t.Fatalf("refused batch returned intents or a grant: %+v %v", intents, granted)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("mixed batch changed the ledger")
			}
		})
	}
}

// Retiring one member can let its action ID be minted again while another
// member still runs. The same batch ID then names mixed attempt states,
// which must refuse without changing either member.
func TestAdmissionLedgerExecuteRefusesRemintedBatchMember(t *testing.T) {
	for _, runningFirst := range []bool{false, true} {
		name := "reserved first"
		if runningFirst {
			name = "running first"
		}
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			running := f.reservedAt("192.0.2.10", ledgerT0.Add(2*admission.HistoryTarget))
			ended := f.reservedAt("192.0.2.11", ledgerT0.Add(time.Hour))
			ids := []admission.ActionID{running.Attempt.ID, ended.Attempt.ID}
			if _, granted, err := f.l.ExecuteBatch(ids); err != nil || !granted {
				t.Fatalf("initial batch: %v %v", granted, err)
			}
			if _, _, err := f.l.Finish(ended.Attempt.ID, admission.DispositionApplied); err != nil {
				t.Fatal(err)
			}
			f.ackAuditStates(ended.Attempt.ID, admission.StateReserved, admission.StateExecuting, admission.StateVerified)
			f.tickAt(ledgerT0.Add(admission.HistoryTarget))
			if _, found := f.historyEntry(ended.Attempt.Candidate); found {
				t.Fatal("ended member's history did not retire")
			}
			root := f.published(evidenceSpec{target: "192.0.2.11", cursor: "reminted=1"})
			_, id := f.enqueue(f.request("192.0.2.11", root))
			_, reminted, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
			if err != nil || !granted || reminted.Attempt.ID != ended.Attempt.ID {
				t.Fatalf("reminted reservation: %+v %v %v", reminted, granted, err)
			}
			if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("valid mixed history refused: %v", err)
			}
			if !runningFirst {
				ids[0], ids[1] = ids[1], ids[0]
			}
			before := f.snapshot()
			intents, granted, err := f.l.ExecuteBatch(ids)
			wantLedgerErr(t, "mixed batch", err, admission.ErrTransitionConflict)
			if granted || intents != nil {
				t.Fatalf("refused batch returned intents or a grant: %+v %v", intents, granted)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("mixed batch changed the ledger")
			}
		})
	}
}
