package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func (f *ledgerFixture) ceilingState() admission.CeilingState {
	f.t.Helper()
	var s admission.CeilingState
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		s, err = loadCeiling(tx)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return s
}

// ledgerCharge is a charge for attempt seq of a fixture candidate.
func (f *ledgerFixture) ledgerCharge(at time.Time, seq uint32, lane admission.Lane, elapsed time.Duration) admission.Charge {
	f.t.Helper()
	req := f.request("192.0.2.99", "")
	cand, err := admission.CandidateKey{Kind: req.Kind, Target: req.Target, Episode: req.Episode, Generation: seq}.ID()
	if err != nil {
		f.t.Fatal(err)
	}
	a, err := admission.NewAttempt(cand, 1)
	if err != nil {
		f.t.Fatal(err)
	}
	return admission.Charge{At: at, Action: a.ID, Lane: lane, Cost: 1, Elapsed: elapsed}
}

// putCharge stores a charge record; with count it is also added to its
// lane's usage, as a reservation would.
func putCharge(tx *bolt.Tx, c admission.Charge, count bool) error {
	key, err := c.Key()
	if err != nil {
		return err
	}
	data, err := c.MarshalBinary()
	if err != nil {
		return err
	}
	if err = tx.Bucket([]byte(admissionChargesBucket)).Put(key, data); err != nil || !count {
		return err
	}
	s, err := loadCeilingState(tx)
	if err != nil {
		return err
	}
	if c.Lane == admission.LaneGeneral {
		s.General.Used += c.Cost
	} else {
		s.Reserved.Used += c.Cost
	}
	return putCeilingState(tx, s)
}

// Opening proves the stored charges against the ceiling: they must decode,
// add up to each lane's usage and not postdate the ceiling's elapsed time.
func TestAdmissionLedgerOpenChecksCharges(t *testing.T) {
	counted := func(f *ledgerFixture) error {
		return f.db.bolt.Update(func(tx *bolt.Tx) error {
			if err := putCharge(tx, f.ledgerCharge(ledgerT0, 1, admission.LaneGeneral, 0), true); err != nil {
				return err
			}
			return putCharge(tx, f.ledgerCharge(ledgerT0.Add(time.Hour), 2, admission.LaneDirect, 0), true)
		})
	}
	f := newLedgerFixture(t)
	if err := counted(f); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("consistent charges: %v", err)
	}
	for name, damage := range map[string]func(f *ledgerFixture, tx *bolt.Tx) error{
		"uncounted charge": func(f *ledgerFixture, tx *bolt.Tx) error {
			return putCharge(tx, f.ledgerCharge(ledgerT0, 3, admission.LaneDirect, 0), false)
		},
		"usage without a charge": func(_ *ledgerFixture, tx *bolt.Tx) error {
			s, err := loadCeilingState(tx)
			if err != nil {
				return err
			}
			s.General.Used++
			return putCeilingState(tx, s)
		},
		"charge after the ceiling's elapsed time": func(f *ledgerFixture, tx *bolt.Tx) error {
			return putCharge(tx, f.ledgerCharge(ledgerT0, 3, admission.LaneGeneral, time.Nanosecond), true)
		},
		"damaged charge": func(f *ledgerFixture, tx *bolt.Tx) error {
			key, err := f.ledgerCharge(ledgerT0, 3, admission.LaneGeneral, 0).Key()
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(admissionChargesBucket)).Put(key, []byte("damaged"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			if err := counted(f); err != nil {
				t.Fatal(err)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(f, tx) }); err != nil {
				t.Fatal(err)
			}
			before := dbSnapshot(t, f.db)
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("err = %v, want a corrupt record", err)
			}
			if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
				t.Fatal("a refused open changed the ledger")
			}
		})
	}
}

func TestAdmissionLedgerUpgradeRefusesPartialCeiling(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(map[bool]string{false: "record", true: "bucket"}[nested], func(t *testing.T) {
			f := newLedgerFixture(t)
			f.schemaTwo()
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				state := tx.Bucket([]byte(admissionQueueStateBucket))
				if nested {
					_, err := state.CreateBucket(ceilingStateKey)
					return err
				}
				return putCeilingState(tx, admission.CeilingState{Fill: true})
			}); err != nil {
				t.Fatal(err)
			}
			db := f.copyDatabase()
			before := dbSnapshot(t, db)
			if _, err := OpenAdmissionLedger(db, f.reg); !isCorrupt(err) {
				t.Fatalf("partial ceiling accepted: %v", err)
			}
			if !reflect.DeepEqual(before, dbSnapshot(t, db)) {
				t.Fatal("refused upgrade changed partial state")
			}
		})
	}
}

// A failure after both upgrades rolls back their buckets and schema marker.
func TestAdmissionLedgerUpgradeRollsBackAfterCeiling(t *testing.T) {
	for _, schema := range []int{1, 2} {
		f := newLedgerFixture(t)
		f.queued()
		if schema == 1 {
			f.schemaOne()
		} else {
			f.schemaTwo()
		}
		if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionClockKey, []byte("damaged"))
		}); err != nil {
			t.Fatal(err)
		}
		db := f.copyDatabase()
		before := dbSnapshot(t, db)
		if _, err := OpenAdmissionLedger(db, f.reg); !isCorrupt(err) {
			t.Fatalf("schema %d late upgrade failure: %v", schema, err)
		}
		if !reflect.DeepEqual(before, dbSnapshot(t, db)) {
			t.Fatalf("schema %d upgrade committed before open completed", schema)
		}
	}
}
