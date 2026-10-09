package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// A failed retirement commits no partial unpin, intent deletion or event.
func TestAdmissionLedgerRetirementIsAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Minute)
	u := f.unknownAt("192.0.2.10", expires)
	f.ackAll()
	f.tickAt(expires)
	before := f.snapshot()
	f.failNext("retire")
	c, a, granted, err := f.l.RetireUnproven(u.Attempt.ID)
	if err == nil || granted || !reflect.DeepEqual(c, admission.Candidate{}) || a != (admission.AttemptRecord{}) {
		t.Fatalf("failed retirement: %+v %+v %v %v", c, a, granted, err)
	}
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a failed retirement changed the ledger")
	}
	if _, _, granted, err = f.l.RetireUnproven(u.Attempt.ID); err != nil || !granted {
		t.Fatalf("retry retirement: %v %v", granted, err)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}

// The unknown outcome already owns the event slot; a full reserve can
// retire it without first allocating room and so frees itself.
func TestAdmissionLedgerRetirementFreesAFullReserve(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Minute)
	u := f.unknownAt("192.0.2.10", expires)
	f.ackAll()
	f.tickAt(expires)
	cost := uint64(f.cost(u.Attempt.Candidate))
	f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, 0) })
	before := f.storageState()
	if before.Recovery+before.OutboxBytes() != admission.RecoveryReserveBytes {
		t.Fatal("the reserve is not full")
	}
	if _, _, granted, err := f.l.RetireUnproven(u.Attempt.ID); err != nil || !granted {
		t.Fatalf("retire full reserve: %v %v", granted, err)
	}
	after := f.storageState()
	if after.Recovery != before.Recovery-cost-admission.MaxIntentBytes || after.AuditSlots != before.AuditSlots ||
		after.Recovery+after.OutboxBytes() != admission.RecoveryReserveBytes-cost-admission.MaxIntentBytes {
		t.Fatalf("reserve before %+v, after %+v", before, after)
	}
}

// Retirement makes the history eligible at the original review boundary,
// without deleting it early or leaving it pinned forever.
func TestAdmissionLedgerRetiredUnknownHistoryBecomesRetirable(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Minute)
	u := f.unknownAt("192.0.2.10", expires)
	f.ackAll()
	f.tickAt(expires)
	if _, _, granted, err := f.l.RetireUnproven(u.Attempt.ID); err != nil || !granted {
		t.Fatalf("retire: %v %v", granted, err)
	}
	f.ackAll()
	pressure := func() {
		t.Helper()
		if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
			q, err := f.l.openQueue(tx, f.wall)
			if err != nil {
				return err
			}
			general, _ := admission.HistoryLanes()
			if err = q.retireForRoom(admission.LaneGeneral, general); err != nil {
				return err
			}
			return q.flush()
		}); err != nil {
			t.Fatal(err)
		}
	}
	review := u.Finished.Add(admission.HistoryRetention)
	f.tickAt(review.Add(-time.Nanosecond))
	pressure()
	if _, err := f.l.Candidate(u.Attempt.Candidate); err != nil {
		t.Fatalf("before review boundary: %v", err)
	}
	f.tickAt(review)
	pressure()
	if _, err := f.l.Candidate(u.Attempt.Candidate); err != errCandidateMissing {
		t.Fatalf("at review boundary: %v", err)
	}
	if _, found := f.historyEntry(u.Attempt.Candidate); found || f.storageState().General.Used != 0 || f.storageState().Recovery != 0 {
		t.Fatal("retired history still consumes capacity")
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}

// The event cannot precede an outcome recorded after the effect's expiry.
func TestAdmissionLedgerOpenProvesRetirementAfterOutcome(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Minute)
	a := f.reservedAt("192.0.2.10", expires)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	f.tickAt(expires.Add(time.Minute))
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	f.ackAll()
	if _, _, granted, err := f.l.RetireUnproven(a.Attempt.ID); err != nil || !granted {
		t.Fatalf("retire: %v %v", granted, err)
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return rewriteRow(tx, a.Attempt.ID, func(r *admission.AuditRow) { r.At = expires })
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
		t.Fatalf("event before outcome: %v", err)
	}
}
