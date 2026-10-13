package store

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Settle ends what a previous process left. A handle that granted a
// reservation itself refuses to settle, so a late call cannot end work
// this process still runs; a reopened handle settles it.
func TestAdmissionLedgerSettleRefusesAfterThisHandleReserved(t *testing.T) {
	f := newLedgerFixture(t)
	a := f.reservedAt("192.0.2.10", ledgerT0.Add(time.Hour))
	before := f.snapshot()
	if _, _, err := f.l.Settle(); !errors.Is(err, admission.ErrTransitionConflict) {
		t.Fatalf("settle after a reservation = %v", err)
	}
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("a refused settlement changed the ledger")
	}
	if got, err := f.l.Attempt(a.Attempt.ID); err != nil || got.State != admission.StateReserved {
		t.Fatalf("attempt = %+v, %v", got, err)
	}
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	if failed, unknown, err := l.Settle(); err != nil || failed != 1 || unknown != 0 {
		t.Fatalf("settle on a new handle = %d failed, %d unknown, %v", failed, unknown, err)
	}
}

// An unknown outcome keeps the intent its attempt recorded when it ran;
// one whose intent is gone is a damaged record, not an outcome.
func TestAdmissionLedgerUnknownOutcomeNeedsItsIntent(t *testing.T) {
	for _, operation := range []string{"finish", "readback", "settle"} {
		for _, damage := range []string{"record", "bucket"} {
			t.Run(operation+"/"+damage, func(t *testing.T) {
				f := newLedgerFixture(t)
				a := f.reservedAt("192.0.2.10", ledgerT0.Add(time.Hour))
				if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
					t.Fatal(err)
				}
				switch operation {
				case "readback":
					if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
						t.Fatal(err)
					}
				case "settle":
					l, err := OpenAdmissionLedger(f.db, f.reg)
					if err != nil {
						t.Fatal(err)
					}
					f.l = l
				}
				if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
					if damage == "bucket" {
						return tx.DeleteBucket([]byte(admissionIntentsBucket))
					}
					return tx.Bucket([]byte(admissionIntentsBucket)).Delete([]byte(a.Attempt.ID))
				}); err != nil {
					t.Fatal(err)
				}
				before, held := dbSnapshot(t, f.db), publishedHolds(f.l)
				if operation == "settle" {
					if failed, unknown, err := f.l.Settle(); !isCorrupt(err) || failed != 0 || unknown != 0 {
						t.Fatalf("settle without an intent = %d failed, %d unknown, %v", failed, unknown, err)
					}
				} else {
					c, got, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown)
					if !isCorrupt(err) || !reflect.DeepEqual(c, admission.Candidate{}) || got != (admission.AttemptRecord{}) {
						t.Fatalf("unknown outcome without its intent = %+v, %+v, %v", c, got, err)
					}
				}
				if !reflect.DeepEqual(dbSnapshot(t, f.db), before) || !reflect.DeepEqual(publishedHolds(f.l), held) {
					t.Fatal("a refused outcome changed the ledger or recovery hold")
				}
			})
		}
	}
}

func TestAdmissionLedgerUnknownOutcomeReadbackAfterRetirement(t *testing.T) {
	f := newLedgerFixture(t)
	a := f.unknownAt("192.0.2.10", ledgerT0.Add(time.Hour))
	f.ackAll()
	f.tickAt(a.ExpiresAt)
	for _, retired := range []bool{false, true} {
		if retired {
			if _, _, granted, err := f.l.RetireUnproven(a.Attempt.ID); err != nil || !granted {
				t.Fatalf("retire = %v, %v", granted, err)
			}
		}
		before := f.snapshot()
		c, got, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown)
		if err != nil || got.Attempt != a.Attempt || got.State != admission.StateUnknown || got.Retired != retired || c.State != admission.StateUnknown {
			t.Fatalf("readback (retired=%v) = %+v, %+v, %v", retired, c, got, err)
		}
		if !reflect.DeepEqual(f.snapshot(), before) {
			t.Fatal("readback changed the ledger")
		}
	}
}

func TestAdmissionLedgerSettleAfterUncommittedReservations(t *testing.T) {
	for _, mode := range []string{"observe", "refused", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.queued()
			switch mode {
			case "observe":
				if _, a, granted, err := f.l.Observe(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil || !granted || a.State != admission.StateObserved {
					t.Fatalf("observe: %+v %v %v", a, granted, err)
				}
			case "refused":
				_, _, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall)
				reason, refused := admission.ReasonOf(err)
				if granted || !refused || reason != admission.ReasonInvalid {
					t.Fatalf("refused reserve: %v %v", granted, err)
				}
			case "rollback":
				f.failNext("reserve")
				if _, _, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); granted || err == nil || err.Error() != "injected failure before commit" {
					t.Fatalf("rolled-back reserve: %v %v", granted, err)
				}
			}
			before := f.snapshot()
			if failed, unknown, err := f.l.Settle(); err != nil || failed != 0 || unknown != 0 {
				t.Fatalf("settle: %d %d %v", failed, unknown, err)
			}
			if !reflect.DeepEqual(f.snapshot(), before) {
				t.Fatal("empty settlement changed the ledger")
			}
		})
	}
}

func TestAdmissionLedgerSettleAfterReservationReadback(t *testing.T) {
	for _, running := range []bool{false, true} {
		t.Run(map[bool]string{false: "reserved", true: "running"}[running], func(t *testing.T) {
			f := newLedgerFixture(t)
			a := f.reservedAt("192.0.2.10", ledgerT0.Add(time.Hour))
			if running {
				if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
					t.Fatal(err)
				}
			}
			l, err := OpenAdmissionLedger(f.db, f.reg)
			if err != nil {
				t.Fatal(err)
			}
			f.l = l
			f.tickAt(f.wall)
			before := f.snapshot()
			if _, got, granted, readErr := l.Reserve(a.Attempt.Candidate, 0, time.Time{}); readErr != nil || granted || got.Attempt != a.Attempt {
				t.Fatalf("reservation readback: %+v %v %v", got, granted, readErr)
			}
			if !reflect.DeepEqual(f.snapshot(), before) {
				t.Fatal("reservation readback changed the ledger")
			}
			failed, unknown, err := l.Settle()
			wantFailed, wantUnknown := 1, 0
			if running {
				wantFailed, wantUnknown = 0, 1
			}
			if err != nil || failed != wantFailed || unknown != wantUnknown {
				t.Fatalf("settle after readback: %d failed, %d unknown, %v", failed, unknown, err)
			}
		})
	}
}
