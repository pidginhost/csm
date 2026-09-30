package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// auditRowsOf returns the pending rows of one attempt in key order, which
// is transition order.
func auditRowsOf(t *testing.T, f *ledgerFixture, tx *bolt.Tx, id admission.ActionID) []admission.AuditRow {
	t.Helper()
	var rows []admission.AuditRow
	for _, row := range f.pendingAuditIn(t, tx) {
		if row.Attempt.ID == id {
			rows = append(rows, row)
		}
	}
	return rows
}

// moveAuditRow stores row under another transition, keeping the slot
// totals.
func moveAuditRow(tx *bolt.Tx, row admission.AuditRow, transition uint32) error {
	if err := tx.Bucket([]byte(admissionOutboxBucket)).Delete(row.Key()); err != nil {
		return err
	}
	row.Transition = transition
	return putAuditRowRaw(tx, row, 0)
}

// ackAuditStates acknowledges the named phases of one attempt.
func (f *ledgerFixture) ackAuditStates(id admission.ActionID, states ...admission.State) {
	f.t.Helper()
	var ids []admission.AuditID
	for _, row := range f.pendingAudit() {
		for _, s := range states {
			if row.Attempt.ID == id && row.State == s {
				ids = append(ids, row.ID())
			}
		}
	}
	if len(ids) != len(states) {
		f.t.Fatalf("acknowledged %d rows, want %d", len(ids), len(states))
	}
	if err := f.l.AckAudit(ids); err != nil {
		f.t.Fatal(err)
	}
}

// executedAndFinished runs a fresh candidate's first attempt to outcome d,
// a second apart, and advances the clock a further second.
func (f *ledgerFixture) executedAndFinished(d admission.Disposition) (admission.CandidateID, admission.AttemptRecord) {
	f.t.Helper()
	id, a := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		f.t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Second))
	_, done, err := f.l.Finish(a.Attempt.ID, d)
	if err != nil {
		f.t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Second))
	return id, done
}

// Each case leaves every total balanced and every other proof satisfied,
// so exactly one guard of the audit proof can refuse it.
func TestAdmissionLedgerAuditProofGuardsStandAlone(t *testing.T) {
	type damage func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error
	for name, setup := range map[string]func(f *ledgerFixture) damage{
		"execution before its reservation": func(f *ledgerFixture) damage {
			a := f.retried(2)
			f.tickAt(f.wall.Add(time.Second))
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				f.t.Fatal(err)
			}
			f.ackAuditStates(a.Attempt.ID, admission.StateReserved)
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				row := auditRowsOf(t, f, tx, a.Attempt.ID)[0]
				row.At = a.Reserved.Add(-time.Nanosecond)
				return putAuditRowRaw(tx, row, 0)
			}
		},
		"roots the candidate never had": func(f *ledgerFixture) damage {
			a := f.retried(2)
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				row := auditRowsOf(t, f, tx, a.Attempt.ID)[0]
				row.Roots = []admission.EvidenceID{"ev_ffffffffffffffffffffffffffffffff"}
				return putAuditRowRaw(tx, row, 0)
			}
		},
		"roots changed within an attempt": func(f *ledgerFixture) damage {
			f.nextGeneration()
			primary := f.published(evidenceSpec{cursor: "guard=1"})
			support := f.published(evidenceSpec{producer: f.rep, check: "reputation", cursor: "guard=2"})
			_, id := f.enqueue(f.request("192.0.2.10", primary, support))
			_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
			if err != nil {
				f.t.Fatal(err)
			}
			if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
				f.t.Fatal(err)
			}
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				rows := auditRowsOf(t, f, tx, a.Attempt.ID)
				if len(rows[1].Roots) != 2 {
					t.Fatalf("roots %v", rows[1].Roots)
				}
				row := rows[1]
				row.Roots = row.Roots[:1]
				return putAuditRowRaw(tx, row, 0)
			}
		},
		"execution at its expiry": func(f *ledgerFixture) damage {
			_, a := f.admitted(time.Hour)
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				f.t.Fatal(err)
			}
			f.tickAt(a.ExpiresAt.Add(time.Second))
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				row := auditRowsOf(t, f, tx, a.Attempt.ID)[1]
				row.At = a.ExpiresAt
				return putAuditRowRaw(tx, row, 0)
			}
		},
		"execution after its outcome": func(f *ledgerFixture) damage {
			_, a := f.executedAndFinished(admission.DispositionApplied)
			f.ackAuditStates(a.Attempt.ID, admission.StateVerified)
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				row := auditRowsOf(t, f, tx, a.Attempt.ID)[1]
				row.At = a.Finished.Add(time.Nanosecond)
				return putAuditRowRaw(tx, row, 0)
			}
		},
		"outcome before it was recorded": func(f *ledgerFixture) damage {
			_, a := f.executedAndFinished(admission.DispositionApplied)
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				row := auditRowsOf(t, f, tx, a.Attempt.ID)[2]
				row.At = a.Finished.Add(-time.Nanosecond)
				return putAuditRowRaw(tx, row, 0)
			}
		},
		"execution a step after its reservation": func(f *ledgerFixture) damage {
			_, a := f.executedAndFinished(admission.DispositionApplied)
			f.ackAuditStates(a.Attempt.ID, admission.StateVerified)
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				row := auditRowsOf(t, f, tx, a.Attempt.ID)[1]
				return moveAuditRow(tx, row, row.Transition+1)
			}
		},
		"outcome a step early": func(f *ledgerFixture) damage {
			a := f.retried(2)
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				f.t.Fatal(err)
			}
			if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
				f.t.Fatal(err)
			}
			f.ackAuditStates(a.Attempt.ID, admission.StateExecuting)
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				row := auditRowsOf(t, f, tx, a.Attempt.ID)[1]
				return moveAuditRow(tx, row, row.Transition-1)
			}
		},
		"failure beyond its reservation's steps": func(f *ledgerFixture) damage {
			id, a := f.executedAndFinished(admission.DispositionFailed)
			if _, err := f.l.Terminate(id, admission.ReasonPolicy); err != nil {
				f.t.Fatal(err)
			}
			f.ackAuditStates(a.Attempt.ID, admission.StateExecuting)
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				row := auditRowsOf(t, f, tx, a.Attempt.ID)[1]
				return moveAuditRow(tx, row, row.Transition+1)
			}
		},
		"failure beyond its execution's steps": func(f *ledgerFixture) damage {
			id, a := f.executedAndFinished(admission.DispositionFailed)
			if _, err := f.l.Terminate(id, admission.ReasonPolicy); err != nil {
				f.t.Fatal(err)
			}
			f.ackAuditStates(a.Attempt.ID, admission.StateReserved)
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				row := auditRowsOf(t, f, tx, a.Attempt.ID)[1]
				return moveAuditRow(tx, row, row.Transition+1)
			}
		},
		"reservation after execution": func(f *ledgerFixture) damage {
			_, a := f.executedAndFinished(admission.DispositionFailed)
			f.ackAuditStates(a.Attempt.ID, admission.StateFailed)
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				row := auditRowsOf(t, f, tx, a.Attempt.ID)[0]
				return moveAuditRow(tx, row, row.Transition+2)
			}
		},
		"repeated reservation": func(f *ledgerFixture) damage {
			_, a := f.admitted(time.Hour)
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				f.t.Fatal(err)
			}
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				row := auditRowsOf(t, f, tx, a.Attempt.ID)[1]
				row.State, row.At = admission.StateReserved, a.Reserved
				return putAuditRowRaw(tx, row, 0)
			}
		},
		"earlier attempt inside a later one, later attempt read first": func(f *ledgerFixture) damage {
			// Rows are read in attempt ID order, which is unrelated to
			// the attempt sequence; this case needs the later attempt's
			// rows read first.
			var a admission.AttemptRecord
			for {
				a = f.retried(2)
				if a.Attempt.ID < a.Attempt.Prev {
					break
				}
			}
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				f.t.Fatal(err)
			}
			if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
				f.t.Fatal(err)
			}
			f.ackAuditStates(a.Attempt.Prev, admission.StateReserved, admission.StateExecuting)
			f.ackAuditStates(a.Attempt.ID, admission.StateExecuting, admission.StateVerified)
			return func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
				earlier := auditRowsOf(t, f, tx, a.Attempt.Prev)[0]
				later := auditRowsOf(t, f, tx, a.Attempt.ID)[0]
				return moveAuditRow(tx, earlier, later.Transition+1)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			damage := setup(f)
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("valid history refused: %v", err)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(t, f, tx) }); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("accepted damage with balanced totals: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("refused open changed the ledger")
			}
		})
	}
}
