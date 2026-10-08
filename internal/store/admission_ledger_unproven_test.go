package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// unknownAt runs a candidate at target and ends its attempt unknown; the
// attempt expires at expires.
func (f *ledgerFixture) unknownAt(target string, expires time.Time) admission.AttemptRecord {
	f.t.Helper()
	a := f.reservedAt(target, expires)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		f.t.Fatal(err)
	}
	if _, done, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		f.t.Fatal(err)
	} else {
		a = done
	}
	return a
}

// An unknown outcome holds the slot of the row that will retire it.
func TestAdmissionLedgerUnknownHoldsItsRetirementRow(t *testing.T) {
	f := newLedgerFixture(t)
	f.unknownAt("192.0.2.10", ledgerT0.Add(time.Hour))
	if rows := f.pendingAudit(); len(rows) != 3 || f.storageState().AuditSlots != 4 {
		t.Fatalf("rows %d, slots %d", len(rows), f.storageState().AuditSlots)
	}
	f.ackAll()
	if slots := f.storageState().AuditSlots; slots != 1 {
		t.Fatalf("slots after delivery = %d", slots)
	}
}

// Once its expiry has passed on a trusted clock, an unknown attempt's
// uncertainty is retired: the outcome stays unknown and counts as nothing
// new, the intent goes, the history and intent leave the recovery reserve
// for the allowance, and the expired_unproven row records the event in the
// slot the outcome held. Again it is a no-op.
func TestAdmissionLedgerRetiresAnExpiredUnknownAttempt(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Hour)
	u := f.unknownAt("192.0.2.10", expires)
	f.ackAll()
	before := f.snapshot()
	_, _, _, err := f.l.RetireUnproven(u.Attempt.ID)
	wantLedgerErr(t, "before expiry", err, admission.ErrNotReady)
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a refused retirement changed the ledger")
	}
	f.tickAt(expires)
	cost := uint64(f.cost(u.Attempt.Candidate))
	storage := f.storageState()
	outcomes := f.l.Status().Outcomes
	c, a, granted, err := f.l.RetireUnproven(u.Attempt.ID)
	if err != nil || !granted {
		t.Fatalf("retire: %v %v", granted, err)
	}
	if a.State != admission.StateUnknown || a.Disposition != admission.DispositionUnknown || !a.Retired || a.Finished != u.Finished {
		t.Fatalf("attempt = %+v", a)
	}
	if c.State != admission.StateUnknown || c.Disposition != admission.DispositionUnknown {
		t.Fatalf("candidate = %+v", c)
	}
	if len(f.intents()) != 0 {
		t.Fatalf("intents = %+v", f.intents())
	}
	got := f.storageState()
	want := storage
	want.Recovery -= cost + admission.MaxIntentBytes
	want.General.Used += cost
	if got != want {
		t.Fatalf("storage = %+v\nwant %+v", got, want)
	}
	if h, found := f.historyEntry(u.Attempt.Candidate); !found || h.Pinned || !h.Eligible.Equal(u.Finished.Add(admission.HistoryRetention)) {
		t.Fatalf("history = %+v, %v", h, found)
	}
	rows := f.pendingAudit()
	if len(rows) != 1 || rows[0].State != admission.StateUnknown || rows[0].Disposition != admission.DispositionExpiredUnproven ||
		!rows[0].At.Equal(expires) || rows[0].Transition != c.Transitions {
		t.Fatalf("rows = %+v", rows)
	}
	if after := f.l.Status().Outcomes; !reflect.DeepEqual(after, outcomes) {
		t.Fatalf("outcomes %+v -> %+v", outcomes, after)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	before = f.snapshot()
	if _, _, granted, err = f.l.RetireUnproven(u.Attempt.ID); err != nil || granted {
		t.Fatalf("again: %v %v", granted, err)
	}
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a repeated retirement changed the ledger")
	}
	f.ackAll()
	if slots := f.storageState().AuditSlots; slots != 0 {
		t.Fatalf("slots after the retirement row = %d", slots)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}

// Only an unknown attempt past its expiry, on a current and trusted clock,
// can be retired.
func TestAdmissionLedgerRetirementRefusals(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Hour)
	running := f.reservedAt("192.0.2.10", expires)
	applied := f.reservedAt("192.0.2.11", expires)
	for _, a := range []admission.AttemptRecord{running, applied} {
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := f.l.Finish(applied.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	u := f.unknownAt("192.0.2.12", expires)
	f.tickAt(expires)
	before := f.snapshot()
	_, _, _, err := f.l.RetireUnproven(u.Attempt.ID)
	wantLedgerErr(t, "undelivered outcome", err, admission.ErrNotReady)
	for name, a := range map[string]admission.AttemptRecord{"running": running, "applied": applied} {
		_, _, _, err = f.l.RetireUnproven(a.Attempt.ID)
		wantLedgerErr(t, name, err, admission.ErrTransitionConflict)
	}
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a refused retirement changed the ledger")
	}
	f.ackAll()
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = l.RetireUnproven(u.Attempt.ID)
	wantLedgerReason(t, "no current reading", err, admission.ReasonEngineUnavailable)
	// The wall moves a minute further than the elapsed time.
	f.wall, f.since = f.wall.Add(time.Hour+time.Minute), f.since+time.Hour
	if tick, tickErr := f.l.Tick(admission.ClockReading{Wall: f.wall, BootID: ledgerBoot, SinceBoot: f.since}); tickErr != nil || !tick.Degraded {
		t.Fatalf("tick = %+v, %v", tick, tickErr)
	}
	before = f.snapshot()
	_, _, _, err = f.l.RetireUnproven(u.Attempt.ID)
	wantLedgerReason(t, "degraded clock", err, admission.ReasonEngineUnavailable)
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a refused retirement changed the ledger")
	}
}

// Opening proves a retirement against its records: a retired attempt has
// no intent, no pinned history and no future row, and its row cannot be
// dated before the expiry; an unretired unknown keeps its slot.
func TestAdmissionLedgerOpenProvesRetirement(t *testing.T) {
	expires := ledgerT0.Add(time.Hour)
	setup := func(t *testing.T, retire bool) (*ledgerFixture, admission.AttemptRecord) {
		f := newLedgerFixture(t)
		u := f.unknownAt("192.0.2.10", expires)
		f.ackAll()
		f.tickAt(expires)
		if retire {
			if _, _, _, err := f.l.RetireUnproven(u.Attempt.ID); err != nil {
				t.Fatal(err)
			}
		}
		return f, u
	}
	for name, tc := range map[string]struct {
		retire bool
		damage func(*testing.T, *bolt.Tx, admission.AttemptRecord) error
	}{
		"retired attempt keeps its intent": {true, func(_ *testing.T, tx *bolt.Tx, u admission.AttemptRecord) error {
			c, err := loadCandidate(tx, u.Attempt.Candidate)
			if err != nil {
				return err
			}
			return putIntent(tx, admission.Intent{Action: u.Attempt.ID, Batch: batchOfID(u.Attempt.ID), Kind: c.Key.Kind, Target: c.Key.Target, ExpiresAt: u.ExpiresAt})
		}},
		"retired attempt stays pinned": {true, func(_ *testing.T, tx *bolt.Tx, u admission.AttemptRecord) error {
			h, _, err := loadHistoryEntry(tx, u.Attempt.Candidate)
			if err != nil {
				return err
			}
			h.Pinned, h.Eligible = true, time.Time{}
			if err = tx.Bucket([]byte(admissionHistoryBucket)).Put([]byte(u.Attempt.Candidate), mustEncode(h)); err != nil {
				return err
			}
			return adjustStorage(tx, func(s *admission.StorageState) {
				s.Recovery += uint64(h.Charged()) + admission.MaxIntentBytes
				s.General.Used -= uint64(h.General)
			})
		}},
		"retirement row before the expiry": {true, func(_ *testing.T, tx *bolt.Tx, u admission.AttemptRecord) error {
			return rewriteRow(tx, u.Attempt.ID, func(r *admission.AuditRow) { r.At = u.Finished })
		}},
		"retirement row of an unretired attempt": {true, func(_ *testing.T, tx *bolt.Tx, u admission.AttemptRecord) error {
			a, err := loadAttempt(tx, u.Attempt.ID)
			if err != nil {
				return err
			}
			a.Retired = false
			return putAttempt(tx, a)
		}},
		"unknown without its retirement slot": {false, func(_ *testing.T, tx *bolt.Tx, _ admission.AttemptRecord) error {
			return adjustStorage(tx, func(s *admission.StorageState) { s.AuditSlots-- })
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f, u := setup(t, tc.retire)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return tc.damage(t, tx, u) }); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("open = %v", err)
			}
		})
	}
}

func batchOfID(id admission.ActionID) admission.BatchID {
	b, err := admission.NewBatchID([]admission.ActionID{id})
	if err != nil {
		panic(err)
	}
	return b
}

func mustEncode(v interface{ MarshalBinary() ([]byte, error) }) []byte {
	data, err := v.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return data
}

// rewriteRow replaces the last pending audit row of attempt id.
func rewriteRow(tx *bolt.Tx, id admission.ActionID, edit func(*admission.AuditRow)) error {
	outbox := tx.Bucket([]byte(admissionOutboxBucket))
	prefix := admission.AuditPrefix(id)
	var last admission.AuditRow
	var key []byte
	cur := outbox.Cursor()
	for k, v := cur.Seek(prefix); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == string(prefix); k, v = cur.Next() {
		r, err := admission.UnmarshalAuditRow(v)
		if err != nil {
			return err
		}
		last, key = r, append([]byte(nil), k...)
	}
	edit(&last)
	data, err := last.MarshalBinary()
	if err != nil {
		return err
	}
	return outbox.Put(key, data)
}
