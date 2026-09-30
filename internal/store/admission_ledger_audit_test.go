package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// pendingAudit reads every unacknowledged audit row.
func (f *ledgerFixture) pendingAudit() []admission.AuditRow {
	f.t.Helper()
	rows, err := f.l.PendingAudit(int(admission.MaxAuditSlots))
	if err != nil {
		f.t.Fatal(err)
	}
	return rows
}

// ackAll acknowledges every pending audit row, as the audit consumer does.
func (f *ledgerFixture) ackAll() {
	f.t.Helper()
	var ids []admission.AuditID
	for _, r := range f.pendingAudit() {
		ids = append(ids, r.ID())
	}
	if err := f.l.AckAudit(ids); err != nil {
		f.t.Fatal(err)
	}
}

func (f *ledgerFixture) entryTier(id admission.CandidateID) admission.Tier {
	f.t.Helper()
	var tier admission.Tier
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		e, err := loadQueueEntry(tx, id)
		tier = e.Tier
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return tier
}

// Reserve, Execute and Finish each write the row of their transition in
// their own transaction; a readback writes none. The reservation holds a
// slot for each of its attempt's rows, so the slots stay put until the
// rows are acknowledged.
func TestAdmissionLedgerWritesAnAuditRowPerTransition(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	base := f.storageState().AuditSlots
	tier := f.entryTier(id)
	c, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := admission.NewAuditRow(c, a, tier, f.wall)
	if rows := f.pendingAudit(); len(rows) != 1 || !reflect.DeepEqual(rows[0], want) {
		t.Fatalf("reservation rows = %+v\nwant %+v", rows, want)
	}
	if got := f.storageState().AuditSlots; got != base+admission.AuditStepsPerAttempt {
		t.Fatalf("slots after reserving = %d", got)
	}
	if _, _, granted, readErr := f.l.Reserve(id, 0, time.Time{}); readErr != nil || granted {
		t.Fatalf("readback: %v %v", granted, readErr)
	}
	f.tickAt(f.wall.Add(time.Second))
	c, a, _, err = f.l.Execute(a.Attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	executed, _ := admission.NewAuditRow(c, a, tier, f.wall)
	if _, _, again, readErr := f.l.Execute(a.Attempt.ID); readErr != nil || again {
		t.Fatalf("execute readback: %v %v", again, readErr)
	}
	f.tickAt(f.wall.Add(time.Second))
	c, a, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied)
	if err != nil {
		t.Fatal(err)
	}
	finished, _ := admission.NewAuditRow(c, a, tier, f.wall)
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	rows := f.pendingAudit()
	if len(rows) != 3 || !reflect.DeepEqual(rows[1], executed) || !reflect.DeepEqual(rows[2], finished) {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].Transition >= rows[1].Transition || rows[1].Transition >= rows[2].Transition {
		t.Fatal("rows do not follow the candidate's transitions")
	}
	if got := f.storageState().AuditSlots; got != base+admission.AuditStepsPerAttempt {
		t.Fatalf("slots after finishing = %d", got)
	}
	f.ackAll()
	if got := f.storageState().AuditSlots; got != base || len(f.pendingAudit()) != 0 {
		t.Fatalf("slots after acknowledging = %d", got)
	}
}

// An attempt that never ran writes two rows: its third slot returns when it
// finishes.
func TestAdmissionLedgerFinishWithoutExecuteReleasesASlot(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	base := f.storageState().AuditSlots
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	if rows := f.pendingAudit(); len(rows) != 2 || rows[1].State != admission.StateFailed {
		t.Fatalf("rows = %+v", rows)
	}
	if got := f.storageState().AuditSlots; got != base+2 {
		t.Fatalf("slots = %d, want the two written rows", got)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen: %v", err)
	}
}

// A reservation needs room in the reserve for its attempt's rows as well
// as for its history (ruling 2), and so does a schedule's pick.
func TestAdmissionLedgerReserveNeedsRoomForItsAuditRows(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	need := uint64(f.cost(id)) + admission.AttemptAuditBytes
	f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, need-1) })
	if picks := f.schedule(admission.ScheduleLimits{General: 10, Members: 10}); len(picks) != 0 {
		t.Fatalf("picked without room for its rows: %+v", picks)
	}
	before := f.snapshot()
	_, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "no room for the rows", err, admission.ReasonPendingRecovery)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused reservation changed the ledger")
	}
	f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, need) })
	if picks := f.schedule(admission.ScheduleLimits{General: 10, Members: 10}); len(picks) != 1 {
		t.Fatalf("picks with room = %+v", picks)
	}
	if _, _, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil || !granted {
		t.Fatalf("with room: %v %v", granted, err)
	}
}

// An acknowledgement removes the rows it names and returns their slots, in
// one transaction. Rows already acknowledged are skipped, so a repeated
// acknowledgement changes nothing.
func TestAdmissionLedgerAckAuditIsIdempotent(t *testing.T) {
	f := newLedgerFixture(t)
	f.applied(time.Hour)
	rows := f.pendingAudit()
	base := f.storageState().AuditSlots
	if err := f.l.AckAudit([]admission.AuditID{rows[0].ID()}); err != nil {
		t.Fatal(err)
	}
	if got := f.storageState().AuditSlots; got != base-1 || len(f.pendingAudit()) != 2 {
		t.Fatalf("slots = %d after one acknowledgement", got)
	}
	before := f.snapshot()
	if err := f.l.AckAudit([]admission.AuditID{rows[0].ID(), rows[0].ID()}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a repeated acknowledgement changed the ledger")
	}
	if err := f.l.AckAudit([]admission.AuditID{{Action: "act_x", Transition: 1}}); err == nil {
		t.Fatal("a malformed acknowledgement was accepted")
	}
	f.failNext("audit")
	if err := f.l.AckAudit([]admission.AuditID{rows[1].ID()}); err == nil {
		t.Fatal("injected failure")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed acknowledgement changed the ledger")
	}
}

// Spec 5.4: ended history is retired only after its audit rows are
// acknowledged. Until then it has no retirement key, so neither its target
// nor pressure retires it; the last acknowledgement writes the keys. A
// pinned outcome gets none either way.
func TestAdmissionLedgerRetirementWaitsForAudit(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.applied(time.Hour)
	unknownID, a := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	if keys := retireKeysIn(t, f.db); len(keys) != 0 {
		t.Fatalf("keys before acknowledgement: %v", keys)
	}
	f.tickAt(f.wall.Add(admission.HistoryTarget + time.Hour))
	if _, err := f.l.Candidate(id); err != nil {
		t.Fatalf("history retired before its rows were acknowledged: %v", err)
	}
	rows := f.pendingAudit()
	var mine []admission.AuditID
	for _, r := range rows {
		if r.Attempt.Candidate == id {
			mine = append(mine, r.ID())
		}
	}
	if err := f.l.AckAudit(mine[:len(mine)-1]); err != nil {
		t.Fatal(err)
	}
	if keys := retireKeysIn(t, f.db); len(keys) != 0 {
		t.Fatalf("keys with a row still pending: %v", keys)
	}
	f.ackAll()
	h, _ := f.historyEntry(id)
	want, _ := h.RetireKeys(id)
	keys := retireKeysIn(t, f.db)
	if len(keys) != len(want) {
		t.Fatalf("keys after acknowledgement = %v, want %d", keys, len(want))
	}
	for _, k := range want {
		if !keys[string(k)] {
			t.Fatalf("missing key %q", k)
		}
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	f.tickAt(f.wall.Add(time.Second))
	if _, err := f.l.Candidate(id); err != errCandidateMissing {
		t.Fatalf("acknowledged history past its target: %v", err)
	}
	if _, err := f.l.Candidate(unknownID); err != nil {
		t.Fatalf("pinned history: %v", err)
	}
}

// Acknowledgement precedes retirement, so a retired candidate leaves no
// rows: a later generation that re-mints its action ID starts clean.
func TestAdmissionLedgerRetiredActionLeavesNoRows(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.applied(time.Hour)
	first, _ := admission.NewAttempt(id, 1)
	f.ackAll()
	f.tickAt(f.wall.Add(admission.HistoryTarget + time.Hour))
	if _, err := f.l.Candidate(id); err != errCandidateMissing {
		t.Fatalf("not retired: %v", err)
	}
	again := f.queued()
	if again != id {
		t.Fatalf("same key made another candidate %s", again)
	}
	_, a, _, err := f.l.Reserve(again, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil || a.Attempt.ID != first.ID {
		t.Fatalf("re-minted attempt %s, %v", a.Attempt.ID, err)
	}
	rows := f.pendingAudit()
	if len(rows) != 1 || rows[0].Attempt.ID != first.ID || rows[0].State != admission.StateReserved {
		t.Fatalf("rows = %+v", rows)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen: %v", err)
	}
}

// Opening checks each attempt's rows and slots: no row after the
// candidate's transitions, and every slot an outstanding attempt holds.
func TestAdmissionLedgerRefusesDamagedAuditRows(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error{
		"row after the candidate's transitions": func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
			row := f.pendingAuditIn(t, tx)[0]
			if err := tx.Bucket([]byte(admissionOutboxBucket)).Delete(row.Key()); err != nil {
				return err
			}
			row.Transition += 5
			return putAuditRowRaw(tx, row, 0)
		},
		"outstanding slot missing": func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
			return adjustStorage(tx, func(s *admission.StorageState) { s.AuditSlots-- })
		},
		"row acknowledged and slot kept": func(t *testing.T, f *ledgerFixture, tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionOutboxBucket)).Delete(f.pendingAuditIn(t, tx)[0].Key())
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.queued()
			if _, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(t, f, tx) }); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("err = %v, want a corrupt record", err)
			}
		})
	}
}

// retried reserves attempt seq of a fresh candidate after seq-1 attempts
// that ran and failed.
func (f *ledgerFixture) retried(seq uint32) admission.AttemptRecord {
	f.t.Helper()
	id, a := f.admitted(time.Hour)
	for n := uint32(1); n < seq; n++ {
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			f.t.Fatal(err)
		}
		if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
			f.t.Fatal(err)
		}
		f.tickAt(f.wall.Add(admission.RetryBackoff(n)))
		var err error
		if _, a, _, err = f.l.Reserve(id, admission.LaneGeneral, time.Time{}); err != nil {
			f.t.Fatal(err)
		}
	}
	return a
}

// Balanced totals and valid keys cannot disguise a different, repeated or
// extra step. Acknowledgement may remove any subset of the genuine steps.
// The executing rows sit on a retried attempt: only the transitions of
// earlier attempts let such a row name a transition its candidate made.
func TestAdmissionLedgerAuditProofChecksSteps(t *testing.T) {
	for _, name := range []string{"unexecuted", "row beyond the attempt's steps", "wrong outcome", "repeated step"} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			var current admission.AttemptRecord
			switch name {
			case "unexecuted":
				current = f.retried(2)
			case "row beyond the attempt's steps":
				current = f.retried(3)
			default:
				f.applied(time.Hour)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				rows := f.pendingAuditIn(t, tx)
				row, slots := rows[0], uint64(0)
				for _, r := range rows {
					if r.Attempt.ID == current.Attempt.ID {
						row = r
					}
				}
				switch name {
				case "unexecuted":
					row.State = admission.StateExecuting
				case "row beyond the attempt's steps":
					row.Transition--
					row.State, slots = admission.StateExecuting, 1
				case "wrong outcome":
					row = rows[len(rows)-1]
					row.State, row.Disposition = admission.StateUnknown, admission.DispositionUnknown
				case "repeated step":
					row = rows[1]
					row.State = admission.StateReserved
				}
				return putAuditRowRaw(tx, row, slots)
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("balanced step damage accepted: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("failed open changed the ledger")
			}
		})
	}
}

func (f *ledgerFixture) pendingAuditIn(t *testing.T, tx *bolt.Tx) []admission.AuditRow {
	t.Helper()
	var out []admission.AuditRow
	if err := tx.Bucket([]byte(admissionOutboxBucket)).ForEach(func(k, v []byte) error {
		if k[0] != 'a' {
			return nil
		}
		r, err := admission.UnmarshalAuditRow(v)
		out = append(out, r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// putAuditRowRaw stores a row and adds slots to the storage record.
func putAuditRowRaw(tx *bolt.Tx, row admission.AuditRow, slots uint64) error {
	v, err := row.MarshalBinary()
	if err != nil {
		return err
	}
	if err = tx.Bucket([]byte(admissionOutboxBucket)).Put(row.Key(), v); err != nil {
		return err
	}
	return adjustStorage(tx, func(s *admission.StorageState) { s.AuditSlots += slots })
}

// An upgrade holds the slots of the rows outstanding attempts may still
// write: two for a reserved attempt, one for an executing one.
func TestAdmissionLedgerUpgradeHoldsOutstandingSlots(t *testing.T) {
	f := newLedgerFixture(t)
	f.admitted(time.Hour)
	_, executing := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(executing.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	f.schemaFour()
	db := f.copyDatabase()
	l, err := OpenAdmissionLedger(db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := l.Storage()
	if err != nil || s.AuditSlots != 3 {
		t.Fatalf("upgraded slots = %d, %v", s.AuditSlots, err)
	}
	if rows, err := l.PendingAudit(10); err != nil || len(rows) != 0 {
		t.Fatalf("upgrade invented rows: %+v, %v", rows, err)
	}
}

// The ending of a finish comes after its row: acknowledging the earlier
// rows first does not let the ending write retirement keys while the
// outcome's own row waits.
func TestAdmissionLedgerFinishRowPrecedesTheEnding(t *testing.T) {
	f := newLedgerFixture(t)
	_, a := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	f.ackAll()
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	if keys := retireKeysIn(t, f.db); len(keys) != 0 {
		t.Fatalf("keys while the outcome row waits: %v", keys)
	}
	if rows := f.pendingAudit(); len(rows) != 1 || rows[0].State != admission.StateVerified {
		t.Fatalf("rows = %+v", rows)
	}
}

// Rows are read in bounded batches and a damaged or misfiled row refuses
// the read and the acknowledgement; a step never overwrites a row.
func TestAdmissionLedgerAuditRefusesDamage(t *testing.T) {
	f := newLedgerFixture(t)
	f.applied(time.Hour)
	if rows, err := f.l.PendingAudit(2); err != nil || len(rows) != 2 {
		t.Fatalf("a batch of two = %d rows, %v", len(rows), err)
	}
	if err := f.l.AckAudit([]admission.AuditID{{Action: f.pendingAudit()[0].Attempt.ID}}); err == nil {
		t.Fatal("an acknowledgement without a transition was accepted")
	}
	misfile := func(f *ledgerFixture) (admission.AuditRow, admission.AuditID) {
		var row admission.AuditRow
		var other admission.AuditID
		if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
			row = f.pendingAuditIn(t, tx)[0]
			other = row.ID()
			other.Transition += 10
			v, _ := row.MarshalBinary()
			return tx.Bucket([]byte(admissionOutboxBucket)).Put(other.Key(), v)
		}); err != nil {
			t.Fatal(err)
		}
		return row, other
	}
	_, other := misfile(f)
	if _, err := f.l.PendingAudit(10); !isCorrupt(err) {
		t.Fatalf("read over a misfiled row: %v", err)
	}
	before := f.snapshot()
	if err := f.l.AckAudit([]admission.AuditID{other}); !isCorrupt(err) {
		t.Fatalf("acknowledging a misfiled row: %v", err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused acknowledgement changed the ledger")
	}

	g := newLedgerFixture(t)
	_, a := g.admitted(time.Hour)
	if err := g.db.bolt.Update(func(tx *bolt.Tx) error {
		row := g.pendingAuditIn(t, tx)[0]
		row.Transition++
		return putAuditRowRaw(tx, row, 0)
	}); err != nil {
		t.Fatal(err)
	}
	before = g.snapshot()
	if _, _, _, err := g.l.Execute(a.Attempt.ID); !isCorrupt(err) {
		t.Fatalf("a step over a stored row: %v", err)
	}
	if !reflect.DeepEqual(before, g.snapshot()) {
		t.Fatal("a refused step changed the ledger")
	}
}
