package store

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// A first startup has no work to settle and no stored clock yet.
func TestAdmissionLedgerSettleBeforeFirstClock(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	reg, _, _, _ := newLedgerRegistry(t)
	for range 2 {
		l, openErr := OpenAdmissionLedger(db, reg)
		if openErr != nil {
			t.Fatal(openErr)
		}
		before := dbSnapshot(t, db)
		failed, unknown, settleErr := l.Settle()
		if settleErr != nil || failed != 0 || unknown != 0 {
			t.Fatalf("empty settlement = %d failed, %d unknown, %v", failed, unknown, settleErr)
		}
		if !reflect.DeepEqual(dbSnapshot(t, db), before) {
			t.Fatal("empty settlement changed the ledger")
		}
	}
}

// An unfamiliar ledger bucket without metadata cannot prove the absence
// of unresolved work, even when none of this build's buckets exists.
func TestReadUnresolvedIntentsRejectsUnknownLedgerWithoutMeta(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = db.bolt.Update(func(tx *bolt.Tx) error {
		_, createErr := tx.CreateBucket([]byte("adm:future"))
		return createErr
	}); err != nil {
		t.Fatal(err)
	}
	if got, readErr := ReadUnresolvedIntents(db); !isCorrupt(readErr) || got != nil {
		t.Fatalf("ledger without metadata read as empty: %+v, %v", got, readErr)
	}
}

// A missing or inconsistent intent must warn through status and doctor,
// without damaging the other sections or hiding running and unknown work.
func TestAdmissionLedgerUnresolvedStatusProvesIntentLinks(t *testing.T) {
	for _, state := range []admission.State{admission.StateExecuting, admission.StateUnknown} {
		for _, damage := range []string{"missing", "expiry", "target", "kind", "nested", "retired"} {
			if damage == "retired" && state != admission.StateUnknown {
				continue
			}
			t.Run(state.String()+"/"+damage, func(t *testing.T) {
				f := newLedgerFixture(t)
				a := f.reservedAt("192.0.2.10", ledgerT0.Add(time.Hour))
				if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
					t.Fatal(err)
				}
				if state == admission.StateUnknown {
					if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
						t.Fatal(err)
					}
				}
				f.ackAll()
				if damage == "retired" && state == admission.StateUnknown {
					in := f.intents()[a.Attempt.ID]
					f.tickAt(a.ExpiresAt)
					if _, _, _, err := f.l.RetireUnproven(a.Attempt.ID); err != nil {
						t.Fatal(err)
					}
					if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putIntent(tx, in) }); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
						b := tx.Bucket([]byte(admissionIntentsBucket))
						if damage == "missing" || damage == "nested" {
							if err := b.Delete([]byte(a.Attempt.ID)); err != nil {
								return err
							}
							if damage != "missing" {
								_, err := b.CreateBucket([]byte(a.Attempt.ID))
								return err
							}
							return nil
						}
						in, _, err := loadIntent(tx, a.Attempt.ID)
						if err != nil {
							return err
						}
						switch damage {
						case "expiry":
							in.ExpiresAt = in.ExpiresAt.Add(time.Hour)
						case "target":
							in.Target = f.target("192.0.2.11")
						case "kind":
							in.Kind = admission.KindChallenge
						}
						return putIntent(tx, in)
					}); err != nil {
						t.Fatal(err)
					}
				}
				s := f.l.Status()
				if s.Unresolved.Error == "" {
					t.Fatalf("damaged intent reported healthy: %+v", s.Unresolved)
				}
				if s.Clock.Error != "" || s.Queue.Error != "" || s.Storage.Error != "" || s.Outbox.Error != "" {
					t.Fatalf("intent damage affected another section: %+v", s)
				}
				row := admission.DoctorChecks(&s, nil, f.wall)[0]
				if row.Status != admission.DoctorWarn || !strings.Contains(row.Message, "unresolved:") {
					t.Fatalf("doctor hid the damaged section: %+v", row)
				}
			})
		}
	}
}

// Once the event is acknowledged, the stored clock must still prove that
// a retired attempt's expiry and outcome passed. Its flag cannot bypass
// either boundary.
func TestAdmissionLedgerOpenRejectsPrematureRetiredFlag(t *testing.T) {
	for _, boundary := range []string{"expiry", "outcome"} {
		t.Run(boundary, func(t *testing.T) {
			f := newLedgerFixture(t)
			u := f.unknownAt("192.0.2.10", ledgerT0.Add(time.Hour))
			f.ackAll()
			if boundary == "outcome" {
				f.tickAt(u.ExpiresAt)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				a, err := loadAttempt(tx, u.Attempt.ID)
				if err != nil {
					return err
				}
				c, err := loadCandidate(tx, u.Attempt.Candidate)
				if err != nil {
					return err
				}
				h, _, err := loadHistoryEntry(tx, u.Attempt.Candidate)
				if err != nil {
					return err
				}
				s, err := loadStorageState(tx)
				if err != nil {
					return err
				}
				if s, err = s.UnpinHistory(h.General, h.Reserved); err != nil {
					return err
				}
				if s, err = s.ReleaseAudit(1); err != nil {
					return err
				}
				a.Retired, h.Pinned = true, false
				if boundary == "outcome" {
					a.Finished = f.wall.Add(time.Minute)
					h.Ended = a.Finished
				}
				h.Eligible, _ = admission.HistoryTimes(h.Ended, c.ExpiresAt, false)
				c.Transitions++
				if err = deleteIntent(tx, u.Attempt.ID); err != nil {
					return err
				}
				if err = putAttempt(tx, a); err != nil {
					return err
				}
				if err = putCandidate(tx, c); err != nil {
					return err
				}
				if err = putHistoryEntry(tx, u.Attempt.Candidate, h); err != nil {
					return err
				}
				return putStorageState(tx, s)
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("premature retired flag opened: %v", err)
			}
			if !reflect.DeepEqual(f.snapshot(), before) {
				t.Fatal("failed opening changed the ledger")
			}
		})
	}
}
