package store

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
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

// upgradedCeiling reopens the fixture's ledger as an upgraded schema 2
// ledger with limit set: its buckets start empty.
func (f *ledgerFixture) upgradedCeiling(limit uint32) {
	f.t.Helper()
	f.schemaTwo()
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		f.t.Fatal(err)
	}
	f.l = l
	f.tickAt(f.wall)
	if err = f.l.SetCeiling(limit); err != nil {
		f.t.Fatal(err)
	}
}

func TestAdmissionLedgerSetCeiling(t *testing.T) {
	f := newLedgerFixture(t)
	// The fixture has already set a limit; the first limit needs a new
	// ledger that is still waiting to fill its buckets.
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if f.l, err = OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatal(err)
	}
	f.db = db
	s, err := f.l.Ceiling()
	if err != nil || s != (admission.CeilingState{Fill: true}) {
		t.Fatalf("new ledger ceiling = %+v, %v", s, err)
	}
	if err = f.l.SetCeiling(2000); err != nil {
		t.Fatal(err)
	}
	s, err = f.l.Ceiling()
	if err != nil || s.Limit != 2000 || s.Fill || s.General.Units() != 266 || s.Reserved.Units() != 66 {
		t.Fatalf("first limit: %+v %v", s, err)
	}
	for _, limit := range []uint32{200, 2000} {
		if err = f.l.SetCeiling(limit); err != nil {
			t.Fatal(err)
		}
	}
	if s = f.ceilingState(); s.Limit != 2000 || s.General.Units() != 26 || s.Reserved.Units() != 6 {
		t.Fatalf("a later limit must clip and never top up: %+v", s)
	}
	before := f.snapshot()
	for _, bad := range []uint32{0, admission.MaxCeiling + 1} {
		wantLedgerReason(t, "limit out of range", f.l.SetCeiling(bad), admission.ReasonInvalid)
	}
	f.failNext("ceiling")
	if err = f.l.SetCeiling(1); err == nil {
		t.Fatal("injected failure did not abort the limit")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused limit changed the ledger")
	}
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := l.Ceiling(); err != nil || again != s {
		t.Fatalf("reopened ceiling = %+v, %v", again, err)
	}
}

// Credit accrues only from elapsed time within a boot: downtime and a wall
// step earn nothing. At a ceiling of 2000 the reserved lane earns a unit
// every 9 seconds and the general lane one every 2.25 seconds.
func TestAdmissionLedgerTickRefillsTheCeiling(t *testing.T) {
	f := newLedgerFixture(t)
	f.upgradedCeiling(2000)
	f.tickAt(f.wall.Add(9 * time.Second))
	s := f.ceilingState()
	if s.Reserved.Units() != 1 || s.General.Units() != 4 || s.Elapsed != 9*time.Second {
		t.Fatalf("after 9s: %+v", s)
	}
	const otherBoot = "7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d"
	if _, err := f.l.Tick(admission.ClockReading{Wall: f.wall.Add(time.Hour), BootID: otherBoot, SinceBoot: time.Second}); err != nil {
		t.Fatal(err)
	}
	if after := f.ceilingState(); after != s {
		t.Fatalf("a reboot credited downtime: %+v", after)
	}
	if _, err := f.l.Tick(admission.ClockReading{Wall: f.wall.Add(5 * time.Hour), BootID: otherBoot, SinceBoot: 10 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if after := f.ceilingState(); after.Elapsed != s.Elapsed+9*time.Second || after.Reserved.Units() != 2 {
		t.Fatalf("a wall step must earn only the elapsed 9s: %+v", after)
	}
}

// A charge counts until a full window of wall time and of elapsed time have
// both passed; the tick that reaches both releases it and deletes it.
func TestAdmissionLedgerTickReleasesCharges(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(2000); err != nil {
		t.Fatal(err)
	}
	spent := f.wall
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return putCharge(tx, f.ledgerCharge(spent, 1, admission.LaneDirect, 0), true)
	}); err != nil {
		t.Fatal(err)
	}
	f.tickAt(spent.Add(admission.CeilingWindow - time.Nanosecond))
	if s := f.ceilingState(); s.Reserved.Used != 1 {
		t.Fatalf("released inside the window: %+v", s)
	}
	f.tickAt(spent.Add(admission.CeilingWindow))
	if s := f.ceilingState(); s.Reserved.Used != 0 || s.General.Used != 0 {
		t.Fatalf("not released at the window's end: %+v", s)
	}
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		if n := tx.Bucket([]byte(admissionChargesBucket)).Stats().KeyN; n != 0 {
			t.Errorf("released charge still stored: %d", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Downtime and a forward wall step keep a charge until a full window of
// elapsed time has passed; a charge dated in the future counts until its
// own time plus the window.
func TestAdmissionLedgerChargesOutlastTimeGaps(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(2000); err != nil {
		t.Fatal(err)
	}
	spent := f.wall
	elapsed := f.ceilingState().Elapsed
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		if err := putCharge(tx, f.ledgerCharge(spent, 1, admission.LaneGeneral, elapsed), true); err != nil {
			return err
		}
		return putCharge(tx, f.ledgerCharge(spent.Add(time.Hour), 2, admission.LaneDirect, elapsed), true)
	}); err != nil {
		t.Fatal(err)
	}
	const otherBoot = "7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d"
	read := func(wall time.Time, since time.Duration) admission.CeilingState {
		t.Helper()
		if _, err := f.l.Tick(admission.ClockReading{Wall: wall, BootID: otherBoot, SinceBoot: since}); err != nil {
			t.Fatal(err)
		}
		return f.ceilingState()
	}
	// A reboot three hours later credits nothing: both charges stay.
	if s := read(spent.Add(3*time.Hour), time.Minute); s.General.Used != 1 || s.Reserved.Used != 1 {
		t.Fatalf("downtime released a charge: %+v", s)
	}
	// A wall step with little elapsed time releases nothing either.
	if s := read(spent.Add(9*time.Hour), 59*time.Minute); s.General.Used != 1 || s.Reserved.Used != 1 {
		t.Fatalf("a wall step released a charge: %+v", s)
	}
	// A full hour of elapsed time releases the first; the future-dated one
	// is also past its own window by then.
	if s := read(spent.Add(9*time.Hour), time.Hour+time.Minute); s.General.Used != 0 || s.Reserved.Used != 0 {
		t.Fatalf("an elapsed hour did not release both: %+v", s)
	}
}

func TestAdmissionLedgerFutureChargeCountsUntilItsWindowEnds(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(2000); err != nil {
		t.Fatal(err)
	}
	dated := f.wall.Add(30 * time.Minute)
	elapsed := f.ceilingState().Elapsed
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return putCharge(tx, f.ledgerCharge(dated, 1, admission.LaneGeneral, elapsed), true)
	}); err != nil {
		t.Fatal(err)
	}
	f.tickAt(dated.Add(admission.CeilingWindow - time.Nanosecond))
	if s := f.ceilingState(); s.General.Used != 1 {
		t.Fatalf("a future-dated charge left before its own window ended: %+v", s)
	}
	f.tickAt(dated.Add(admission.CeilingWindow))
	if s := f.ceilingState(); s.General.Used != 0 {
		t.Fatalf("a future-dated charge outlived its window: %+v", s)
	}
}

// A failed tick changes neither the clock nor the ceiling, and a damaged
// charge refuses the tick that would release it.
func TestAdmissionLedgerTickMetersAtomically(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(2000); err != nil {
		t.Fatal(err)
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return putCharge(tx, f.ledgerCharge(f.wall, 1, admission.LaneGeneral, 0), true)
	}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	f.failNext("tick")
	if _, err := f.l.Tick(admission.ClockReading{Wall: f.wall.Add(2 * time.Hour), BootID: ledgerBoot, SinceBoot: f.since + 2*time.Hour}); err == nil {
		t.Fatal("injected failure did not abort the tick")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed tick changed the ledger")
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		key, err := f.ledgerCharge(f.wall, 1, admission.LaneGeneral, 0).Key()
		if err != nil {
			return err
		}
		return tx.Bucket([]byte(admissionChargesBucket)).Put(key, []byte("damaged"))
	}); err != nil {
		t.Fatal(err)
	}
	before = f.snapshot()
	if _, err := f.l.Tick(admission.ClockReading{Wall: f.wall.Add(2 * time.Hour), BootID: ledgerBoot, SinceBoot: f.since + 2*time.Hour}); !isCorrupt(err) {
		t.Fatalf("tick over a damaged charge: %v", err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused tick changed the ledger")
	}
}

func TestAdmissionLedgerTickRefusesElapsedOverflow(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(2000); err != nil {
		t.Fatal(err)
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		s, err := loadCeilingState(tx)
		if err != nil {
			return err
		}
		s.Elapsed = time.Duration(1<<63-1) - time.Nanosecond
		return putCeilingState(tx, s)
	}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	_, err := f.l.Tick(admission.ClockReading{Wall: f.wall.Add(2 * time.Nanosecond), BootID: ledgerBoot, SinceBoot: f.since + 2*time.Nanosecond})
	wantLedgerReason(t, "elapsed overflow", err, admission.ReasonEngineUnavailable)
	if !reflect.DeepEqual(before, f.snapshot()) || f.l.current {
		t.Fatal("overflow committed time or left admission enabled")
	}
	f.tickAt(f.wall.Add(time.Nanosecond))
	if got := f.ceilingState().Elapsed; got != time.Duration(1<<63-1) {
		t.Fatalf("failed tick consumed elapsed time: %v", got)
	}
}

func TestAdmissionLedgerTickChecksRetainedCharges(t *testing.T) {
	for _, damage := range []string{"record", "usage", "elapsed"} {
		t.Run(damage, func(t *testing.T) {
			f := newLedgerFixture(t)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				if err := putCharge(tx, f.ledgerCharge(f.wall, 1, admission.LaneGeneral, 0), true); err != nil {
					return err
				}
				tail := f.ledgerCharge(f.wall.Add(time.Second), 2, admission.LaneDirect, 0)
				if damage == "elapsed" {
					tail.Elapsed = time.Nanosecond
				}
				if err := putCharge(tx, tail, damage != "usage"); err != nil {
					return err
				}
				if damage == "record" {
					key, err := tail.Key()
					if err != nil {
						return err
					}
					return tx.Bucket([]byte(admissionChargesBucket)).Put(key, []byte("damaged"))
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			_, err := f.l.Tick(admission.ClockReading{Wall: f.wall.Add(time.Second), BootID: ledgerBoot, SinceBoot: f.since + time.Second})
			if !isCorrupt(err) {
				t.Fatalf("tick ignored retained %s damage: %v", damage, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) || f.l.current {
				t.Fatal("damaged retained charges advanced admission")
			}
		})
	}
}

func TestAdmissionLedgerTickReleasesInKeyOrder(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		s, err := loadCeilingState(tx)
		if err != nil {
			return err
		}
		s.Elapsed = time.Hour
		if err := putCeilingState(tx, s); err != nil {
			return err
		}
		if err := putCharge(tx, f.ledgerCharge(f.wall, 1, admission.LaneDirect, time.Hour), true); err != nil {
			return err
		}
		return putCharge(tx, f.ledgerCharge(f.wall.Add(time.Nanosecond), 2, admission.LaneGeneral, 0), true)
	}); err != nil {
		t.Fatal(err)
	}
	wall := f.wall.Add(2 * time.Hour)
	if _, err := f.l.Tick(admission.ClockReading{Wall: wall, BootID: ledgerBoot, SinceBoot: f.since}); err != nil {
		t.Fatal(err)
	}
	if s := f.ceilingState(); s.General.Used != 1 || s.Reserved.Used != 1 {
		t.Fatalf("a later charge passed a retained head: %+v", s)
	}
	if _, err := f.l.Tick(admission.ClockReading{Wall: wall.Add(time.Hour), BootID: ledgerBoot, SinceBoot: f.since + time.Hour}); err != nil {
		t.Fatal(err)
	}
	if s := f.ceilingState(); s.General.Used != 0 || s.Reserved.Used != 0 {
		t.Fatalf("charges not released after both clocks passed: %+v", s)
	}
}

// charges is every stored charge, oldest first.
func (f *ledgerFixture) charges() []admission.Charge {
	f.t.Helper()
	var out []admission.Charge
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionChargesBucket)).ForEach(func(k, v []byte) error {
			c, err := admission.UnmarshalCharge(k, v)
			out = append(out, c)
			return err
		})
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// Each granted reservation charges its lane once, in its own transaction:
// a readback charges nothing, a retry is charged again, and a failed
// attempt's charge is never refunded.
func TestAdmissionLedgerReserveChargesThePickedLane(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	f.tickAt(f.wall.Add(time.Minute))
	before := f.ceilingState()
	expires := f.wall.Add(time.Hour)
	_, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, expires)
	if err != nil || !granted || a.Lane != admission.LaneGeneral {
		t.Fatalf("reserve: %+v %v %v", a, granted, err)
	}
	s := f.ceilingState()
	if s.General.Used != 1 || s.General.Units() != before.General.Units()-1 || s.Reserved != before.Reserved {
		t.Fatalf("charged ceiling = %+v", s)
	}
	want := admission.Charge{At: f.wall, Action: a.Attempt.ID, Lane: admission.LaneGeneral, Cost: 1, Elapsed: time.Minute}
	if got := f.charges(); len(got) != 1 || got[0] != want {
		t.Fatalf("charges = %+v, want %+v", got, want)
	}
	snap := f.snapshot()
	for _, lane := range []admission.Lane{0, admission.LaneGeneral} {
		_, same, again, readErr := f.l.Reserve(id, lane, time.Time{})
		if readErr != nil || again || same.Attempt != a.Attempt {
			t.Fatalf("readback on lane %s: %+v %v %v", lane, same, again, readErr)
		}
	}
	_, _, _, err = f.l.Reserve(id, admission.LaneDirect, time.Time{})
	wantLedgerErr(t, "readback on another lane", err, admission.ErrTransitionConflict)
	if !reflect.DeepEqual(snap, f.snapshot()) {
		t.Fatal("a readback changed the ledger")
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
	if _, retry, granted, err := f.l.Reserve(id, admission.LaneGeneral, time.Time{}); err != nil || !granted || retry.Attempt.Seq != 2 {
		t.Fatalf("retry: %+v %v %v", retry, granted, err)
	}
	if s = f.ceilingState(); s.General.Used != 2 || len(f.charges()) != 2 {
		t.Fatalf("a retry must be charged again and keep the failed charge: %+v", s)
	}
}

// Only the caller's zero lane is a readback wildcard. An upgraded attempt
// keeps its unknown lane and cannot match a newly supplied nonzero lane.
func TestAdmissionLedgerLegacyReadbackRejectsAnotherLane(t *testing.T) {
	for _, schema := range []int{1, 2} {
		for _, executing := range []bool{false, true} {
			t.Run(fmt.Sprintf("schema=%d/executing=%t", schema, executing), func(t *testing.T) {
				f := newLedgerFixture(t)
				id := f.queued()
				c, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
				if err != nil || !granted {
					t.Fatalf("reserve: %v %v", granted, err)
				}
				if executing {
					if c, a, granted, err = f.l.Execute(a.Attempt.ID); err != nil || !granted {
						t.Fatalf("execute: %v %v", granted, err)
					}
				}
				if schema == 1 {
					f.schemaOne()
				} else {
					f.schemaTwo()
				}
				if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
					t.Fatal(err)
				}
				f.tickAt(f.wall)
				a.Lane = 0
				before := f.snapshot()
				got, same, granted, err := f.l.Reserve(id, 0, time.Time{})
				if err != nil || granted || same != a || !reflect.DeepEqual(got, c) {
					t.Fatalf("legacy readback: %+v %+v %v %v", got, same, granted, err)
				}
				for _, lane := range []admission.Lane{admission.LaneGeneral, admission.LaneDirect, admission.LaneCorroborated, 255} {
					_, _, granted, err = f.l.Reserve(id, lane, time.Time{})
					wantLedgerErr(t, lane.String(), err, admission.ErrTransitionConflict)
					if granted {
						t.Errorf("readback granted work on lane %s", lane)
					}
				}
				if !reflect.DeepEqual(before, f.snapshot()) {
					t.Fatal("legacy readbacks changed the ledger")
				}
			})
		}
	}
}

// Challenge work has its own bound and never charges the block ceiling,
// even before one is set.
func TestAdmissionLedgerChallengeIsNeverCharged(t *testing.T) {
	f := newLedgerFixture(t)
	root := f.published(evidenceSpec{})
	req := f.request("192.0.2.10", root)
	req.Kind = admission.KindChallenge
	_, challenge := f.enqueue(req)
	f.nextGeneration()
	block := f.queued()
	f.schemaTwo()
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = l
	f.tickAt(f.wall)
	// An upgraded ledger saves no history credit. Give it the credit that
	// elapsed time would, without moving the ceiling's clock.
	f.adjustStorage(func(s *admission.StorageState) {
		full := admission.NewStorageState()
		s.General.Credit, s.Reserved.Credit = full.General.Credit, full.Reserved.Credit
	})
	before := f.snapshot()
	_, _, _, err = f.l.Reserve(block, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "block before a ceiling", err, admission.ReasonEngineUnavailable)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused reservation changed the ledger")
	}
	_, _, _, err = f.l.Reserve(challenge, 0, f.wall.Add(time.Hour))
	wantLedgerReason(t, "challenge without a lane", err, admission.ReasonInvalid)
	_, a, granted, err := f.l.Reserve(challenge, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil || !granted || a.Lane != admission.LaneGeneral {
		t.Fatalf("challenge: %+v %v %v", a, granted, err)
	}
	if s := f.ceilingState(); s != (admission.CeilingState{}) || len(f.charges()) != 0 {
		t.Fatalf("a challenge was charged: %+v", s)
	}
}

// The general lane spends only its own credit: once it is spent, a refused
// reservation changes nothing, direct compromise work still reserves on
// the reserved lane, and elapsed time earns the general lane a new unit.
func TestAdmissionLedgerReserveRefusesBeyondTheCeiling(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(10); err != nil {
		t.Fatal(err)
	}
	first := f.queued()
	if _, _, _, err := f.l.Reserve(first, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.nextGeneration()
	second := f.queued()
	before := f.snapshot()
	_, _, _, err := f.l.Reserve(second, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "general lane spent", err, admission.ReasonCeiling)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused reservation changed the ledger")
	}
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.11", cursor: "direct", severity: admission.SeverityCritical})
	_, directID := f.enqueue(f.request("192.0.2.11", direct))
	_, a, _, err := f.l.Reserve(directID, admission.LaneDirect, f.wall.Add(time.Hour))
	if err != nil || a.Lane != admission.LaneDirect {
		t.Fatalf("direct compromise on the reserved lane: %+v %v", a, err)
	}
	if s := f.ceilingState(); s.General.Used != 1 || s.Reserved.Used != 1 {
		t.Fatalf("lanes = %+v", s)
	}
	// A ceiling of 10 gives the general lane 8 units an hour: one every
	// 450 seconds.
	f.tickAt(f.wall.Add(450 * time.Second))
	if _, _, _, err = f.l.Reserve(second, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatalf("after a refill: %v", err)
	}
}

// A reserved lane is rechecked at reservation, since the pick came from an
// earlier transaction. A candidate whose compromise root went stale keeps
// only corroboration: it can no longer use the direct turn but can use the
// corroborated one, or its general turn.
func TestAdmissionLedgerReserveRechecksTheReservedLane(t *testing.T) {
	f := newLedgerFixture(t)
	local := f.published(evidenceSpec{})
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", cursor: "direct", severity: admission.SeverityCritical, age: admission.RootFreshness - time.Second})
	_, id := f.enqueue(f.request("192.0.2.10", local, direct))
	if e, err := f.entry(id); err != nil || !e.Direct {
		t.Fatalf("entry = %+v, %v", e, err)
	}
	f.nextGeneration()
	plain := f.queued()
	_, _, _, err := f.l.Reserve(plain, admission.LaneCorroborated, f.wall.Add(time.Hour))
	wantLedgerErr(t, "local work on a reserved lane", err, admission.ErrLaneIneligible)
	f.tickAt(f.wall.Add(time.Second))
	before := f.snapshot()
	_, _, _, err = f.l.Reserve(id, admission.LaneDirect, f.wall.Add(time.Hour))
	wantLedgerErr(t, "direct turn after the compromise root went stale", err, admission.ErrLaneIneligible)
	_, _, _, err = f.l.Reserve(id, 0, f.wall.Add(time.Hour))
	wantLedgerReason(t, "no lane", err, admission.ReasonInvalid)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused reservation changed the ledger")
	}
	_, a, _, err := f.l.Reserve(id, admission.LaneCorroborated, f.wall.Add(time.Hour))
	if err != nil || a.Lane != admission.LaneCorroborated {
		t.Fatalf("corroborated turn: %+v %v", a, err)
	}
	if s := f.ceilingState(); s.Reserved.Used != 1 || s.General.Used != 0 {
		t.Fatalf("lanes = %+v", s)
	}
	if _, _, _, err = f.l.Reserve(plain, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// The recheck applies current policy: a pick refused by a raised floor is
// refused for its reason, not as merely ineligible, and stays queued for
// the next revalidation to end.
func TestAdmissionLedgerReserveRechecksPolicy(t *testing.T) {
	f, raise := newFloorLedger(t)
	id := f.queued()
	raise(admission.SeverityCritical)
	before := f.snapshot()
	_, _, _, err := f.l.Reserve(id, admission.LaneDirect, f.wall.Add(time.Hour))
	wantLedgerReason(t, "pick below the new floor", err, admission.ReasonPolicy)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused reservation changed the ledger")
	}
}

// Each lane serves at most what the ceiling can charge now: with one unit
// saved in each lane, two direct candidates get one reserved turn and the
// general lane's C3 turn, and the local work waits for the next general
// unit to accrue.
func TestAdmissionLedgerScheduleServesWithinTheCeiling(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(10); err != nil {
		t.Fatal(err)
	}
	var direct []admission.CandidateID
	for i, target := range []string{"192.0.2.11", "192.0.2.12"} {
		root := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: target, cursor: fmt.Sprintf("direct=%d", i), severity: admission.SeverityCritical})
		_, id := f.enqueue(f.request(target, root))
		direct = append(direct, id)
	}
	local := f.fill(2, evidenceSpec{})
	picks := f.schedule(admission.ScheduleLimits{General: 10, Reserved: 10, Members: 10})
	if len(picks) != 2 || picks[0].Lane != admission.LaneDirect || picks[1].Lane != admission.LaneGeneral ||
		!slices.Contains(direct, picks[0].ID) || !slices.Contains(direct, picks[1].ID) {
		t.Fatalf("picks = %+v, direct %v", picks, direct)
	}
	for _, p := range picks {
		if _, _, _, err := f.l.Reserve(p.ID, p.Lane, f.wall.Add(time.Hour)); err != nil {
			t.Fatalf("reserve %+v: %v", p, err)
		}
	}
	if picks = f.schedule(admission.ScheduleLimits{General: 10, Reserved: 10, Members: 10}); len(picks) != 0 {
		t.Fatalf("picks past the ceiling = %+v", picks)
	}
	// The general lane earns a unit every 450 seconds, the reserved lane
	// one every 1800: the ready work wakes the owner for the first.
	if wake, ok, err := f.l.NextWake(); err != nil || !ok || !wake.Equal(f.wall.Add(450*time.Second)) {
		t.Fatalf("budget wake = %v %v, %v", wake, ok, err)
	}
	f.tickAt(f.wall.Add(450 * time.Second))
	picks = f.schedule(admission.ScheduleLimits{General: 10, Reserved: 10, Members: 10})
	if len(picks) != 1 || picks[0].Lane != admission.LaneGeneral || !slices.Contains(local, picks[0].ID) {
		t.Fatalf("after a general unit: %+v, local %v", picks, local)
	}
}

// With a ceiling of 1 only the reserved lane exists: ordinary work is never
// picked and never wakes the owner for budget, only for its deadlines.
func TestAdmissionLedgerCeilingOfOneServesOnlyTheReservedLane(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(1); err != nil {
		t.Fatal(err)
	}
	f.queued()
	if picks := f.schedule(admission.ScheduleLimits{General: 10, Reserved: 10, Members: 10}); len(picks) != 0 {
		t.Fatalf("general work picked with no general lane: %+v", picks)
	}
	if wake, ok, err := f.l.NextWake(); err != nil || !ok || !wake.Equal(f.wall.Add(admission.QueueAgeLimit)) {
		t.Fatalf("wake = %v %v, %v; want only the age-out", wake, ok, err)
	}
	// The reserved lane's history credit does not wake work that cannot
	// use that lane.
	f.adjustStorage(func(s *admission.StorageState) { s.Reserved.Credit -= 1000 * uint64(time.Second) })
	if wake, ok, err := f.l.NextWake(); err != nil || !ok || !wake.Equal(f.wall.Add(admission.QueueAgeLimit)) {
		t.Fatalf("with reserved credit short, wake = %v %v, %v; want only the age-out", wake, ok, err)
	}
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.11", cursor: "direct", severity: admission.SeverityCritical})
	_, id := f.enqueue(f.request("192.0.2.11", direct))
	if picks := f.schedule(admission.ScheduleLimits{General: 10, Reserved: 10, Members: 10}); len(picks) != 1 || picks[0].ID != id || picks[0].Lane != admission.LaneDirect {
		t.Fatalf("direct work on the reserved lane: %+v", picks)
	}
	// With the reserved lane's only unit spent, ordinary work still waits
	// for nothing but its own age-out.
	if _, _, _, err := f.l.Reserve(id, admission.LaneDirect, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if wake, ok, err := f.l.NextWake(); err != nil || !ok || !wake.Equal(f.wall.Add(admission.QueueAgeLimit)) {
		t.Fatalf("with the reserved lane spent, wake = %v %v, %v; want only the age-out", wake, ok, err)
	}
}

func TestAdmissionLedgerReserveRollsBackItsCharge(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	before := f.snapshot()
	ceiling := f.ceilingState()
	f.failNext("reserve")
	_, _, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err == nil || granted {
		t.Fatalf("aborted reservation granted work: %v %v", granted, err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("aborted reservation changed charge, credit or attempt state")
	}
	_, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil || !granted || a.Attempt.Seq != 1 {
		t.Fatalf("retry after rollback: %+v %v %v", a, granted, err)
	}
	if got := f.charges(); len(got) != 1 || got[0].Action != a.Attempt.ID {
		t.Fatalf("retry charges: %+v", got)
	}
	if got := f.ceilingState(); got.General.Used != ceiling.General.Used+1 || got.General.Units() != ceiling.General.Units()-1 || got.Reserved != ceiling.Reserved {
		t.Fatalf("retry spent more than one charge: %+v", got)
	}
}

func TestAdmissionLedgerReopenPreservesSpentCredit(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(10); err != nil {
		t.Fatal(err)
	}
	first := f.queued()
	if _, _, _, err := f.l.Reserve(first, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.nextGeneration()
	second := f.queued()
	before := f.ceilingState()
	f.db = f.copyDatabase()
	var err error
	if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	if err = f.l.SetCeiling(10); err != nil {
		t.Fatal(err)
	}
	if got := f.ceilingState(); got != before {
		t.Fatalf("reload on reopen changed credit: %+v", got)
	}
	_, _, granted, err := f.l.Reserve(second, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "reopen before tick", err, admission.ReasonEngineUnavailable)
	if granted {
		t.Fatal("reopen granted work before tick")
	}
	f.tickAt(f.wall)
	_, _, granted, err = f.l.Reserve(second, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "saved credit exhausted", err, admission.ReasonCeiling)
	if granted || f.ceilingState() != before {
		t.Fatal("reopen manufactured credit")
	}
	f.tickAt(f.wall.Add(450 * time.Second))
	if _, _, granted, err = f.l.Reserve(second, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil || !granted {
		t.Fatalf("same-boot elapsed credit: %v %v", granted, err)
	}
	// After a crash and reopen, the next reading credits only the time since
	// the committed checkpoint. 225 seconds at 8 units an hour is half a
	// unit, below the one-unit cap, so an interval credited again shows.
	spent := f.ceilingState()
	f.db = f.copyDatabase()
	if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(225 * time.Second))
	got := f.ceilingState()
	if got.Elapsed != spent.Elapsed+225*time.Second || got.General.Credit != spent.General.Credit+uint64(time.Hour)/2 {
		t.Fatalf("elapsed credited across the reopen: %+v, spent %+v", got, spent)
	}
}

// A stored charge under the key the next reservation would write is damage:
// the reservation refuses rather than overwrite it and commit usage the
// retained charges no longer prove.
func TestAdmissionLedgerReserveRefusesAChargeCollision(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	next, err := admission.NewAttempt(id, 1)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := f.ceilingState().Elapsed
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		return putCharge(tx, admission.Charge{At: f.wall, Action: next.ID, Lane: admission.LaneGeneral, Cost: 1, Elapsed: elapsed}, true)
	}); err != nil {
		t.Fatal(err)
	}
	if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("a proven charge refused the open: %v", err)
	}
	f.tickAt(f.wall)
	before := f.snapshot()
	_, _, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if !isCorrupt(err) || granted {
		t.Fatalf("reservation over a colliding charge: %v %v", granted, err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused reservation changed the ledger")
	}
}

// Ready work behind a full general allowance, with a unit of credit saved,
// is due when the oldest charge leaves the window, not now.
func TestAdmissionLedgerNextWakeWaitsForTheWindow(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(10); err != nil {
		t.Fatal(err)
	}
	elapsed := f.ceilingState().Elapsed
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		for i := uint32(1); i <= 8; i++ {
			if err := putCharge(tx, f.ledgerCharge(f.wall, i, admission.LaneGeneral, elapsed), true); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.queued()
	if s := f.ceilingState(); s.General.Units() != 1 || s.Budget(admission.LaneGeneral) != 0 {
		t.Fatalf("setup: %+v", s)
	}
	wake, ok, err := f.l.NextWake()
	if err != nil || !ok || !wake.Equal(f.wall.Add(admission.CeilingWindow)) {
		t.Fatalf("wake = %v %v %v, want the window's end", wake, ok, err)
	}
}

// With a ceiling of 1 only the reserved lane runs: once spent, it wakes
// direct compromise work when its unit returns, an hour later.
func TestAdmissionLedgerNextWakeServesTheReservedLane(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(1); err != nil {
		t.Fatal(err)
	}
	var ids []admission.CandidateID
	for _, tc := range []struct{ target, cursor string }{{"192.0.2.11", "directa"}, {"192.0.2.12", "directb"}} {
		root := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: tc.target, cursor: tc.cursor, severity: admission.SeverityCritical})
		_, id := f.enqueue(f.request(tc.target, root))
		ids = append(ids, id)
	}
	if _, _, _, err := f.l.Reserve(ids[0], admission.LaneDirect, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	wake, ok, err := f.l.NextWake()
	if err != nil || !ok || !wake.Equal(f.wall.Add(admission.CeilingWindow)) {
		t.Fatalf("reserved wake = %v %v %v, want the window's end", wake, ok, err)
	}
}

// The reserved-lane recheck reports damage as damage: a damaged root or
// damaged queue bookkeeping refuses the reservation as corrupt, never as
// merely ineligible, and changes nothing.
func TestAdmissionLedgerReserveRecheckReportsDamage(t *testing.T) {
	for name, damage := range map[string]func(root admission.EvidenceID) func(tx *bolt.Tx) error{
		"root": func(root admission.EvidenceID) func(tx *bolt.Tx) error {
			return func(tx *bolt.Tx) error {
				return tx.Bucket([]byte(admissionEvidenceBucket)).Put([]byte(root), []byte("damaged"))
			}
		},
		"queue counters": func(admission.EvidenceID) func(tx *bolt.Tx) error {
			return func(tx *bolt.Tx) error {
				return tx.Bucket([]byte(admissionQueueStateBucket)).Put(queueCountersKey, []byte("damaged"))
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			root := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.11", cursor: "direct", severity: admission.SeverityCritical})
			_, id := f.enqueue(f.request("192.0.2.11", root))
			if err := f.db.bolt.Update(damage(root)); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			_, _, granted, err := f.l.Reserve(id, admission.LaneDirect, f.wall.Add(time.Hour))
			if !isCorrupt(err) || granted {
				t.Fatalf("recheck over damaged %s: %v %v", name, granted, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("a refused reservation changed the ledger")
			}
		})
	}
}

// newUnlimitedLedger replaces the fixture's ledger with a new one on a
// fresh database that has not taken its first limit.
func (f *ledgerFixture) newUnlimitedLedger() {
	f.t.Helper()
	db, err := Open(f.t.TempDir())
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = db.Close() })
	if f.l, err = OpenAdmissionLedger(db, f.reg); err != nil {
		f.t.Fatal(err)
	}
	f.db = db
}

// Spec 5.4 migration: a new ledger takes its first limit and the legacy
// hour's spend in one transaction. The spend counts until its own hour has
// left the window and an hour of elapsed time has passed; it is subtracted
// from the first fill, and neither a second import nor a later limit tops
// the credit up.
func TestAdmissionLedgerImportsLegacySpendOnce(t *testing.T) {
	f := newLedgerFixture(t)
	f.newUnlimitedLedger()
	before := f.snapshot()
	spend := admission.LegacySpend{Units: 100, At: f.wall.Add(20 * time.Minute)}
	f.failNext("ceiling")
	if err := f.l.ImportLegacySpend(2000, spend); err == nil {
		t.Fatal("injected failure did not abort the import")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed import changed the ledger")
	}
	if err := f.l.ImportLegacySpend(2000, spend); err != nil {
		t.Fatal(err)
	}
	s := f.ceilingState()
	if s.Limit != 2000 || s.General.Used != 100 || s.General.Units() != 166 || s.Reserved.Units() != 66 {
		t.Fatalf("imported ceiling = %+v", s)
	}
	after := f.snapshot()
	if err := f.l.ImportLegacySpend(2000, spend); !errors.Is(err, admission.ErrTransitionConflict) {
		t.Fatalf("a second import: %v", err)
	}
	if err := f.l.SetCeiling(2000); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, f.snapshot()) {
		t.Fatal("a second import or a later limit changed the imported ceiling")
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen over imported charges: %v", err)
	}
	f.tickAt(f.wall)
	f.tickAt(spend.At.Add(admission.CeilingWindow - time.Nanosecond))
	if got := f.ceilingState().General.Used; got != 100 {
		t.Fatalf("imported spend left before its hour's window ended: %d", got)
	}
	f.tickAt(spend.At.Add(admission.CeilingWindow))
	if got := f.ceilingState().General.Used; got != 0 {
		t.Fatalf("imported spend outlived its window: %d", got)
	}
}

// A legacy counter that could not be read starts the ledger without credit.
func TestAdmissionLedgerUnknownLegacySpendStartsEmpty(t *testing.T) {
	f := newLedgerFixture(t)
	f.newUnlimitedLedger()
	if err := f.l.ImportLegacySpend(2000, admission.LegacySpend{Unknown: true}); err != nil {
		t.Fatal(err)
	}
	if s := f.ceilingState(); s.Limit != 2000 || s.General.Credit != 0 || s.Reserved.Credit != 0 || s.General.Used != 0 {
		t.Fatalf("unknown spend = %+v", s)
	}
}

func TestAdmissionLedgerReadsImportedSpend(t *testing.T) {
	f := newLedgerFixture(t)
	f.newUnlimitedLedger()
	f.tickAt(f.wall)
	spend := admission.LegacySpend{Units: admission.MaxCeiling + 1, At: f.wall.Add(20 * time.Minute)}
	if err := f.l.ImportLegacySpend(2000, spend); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.ImportedLegacySpend()
	if err != nil || got.Units != admission.MaxCeiling || !got.At.Equal(spend.At) || got.Unknown {
		t.Fatalf("retained import: %+v, %v", got, err)
	}
	f.tickAt(spend.At.Add(admission.CeilingWindow))
	if got, err = f.l.ImportedLegacySpend(); err != nil || got != (admission.LegacySpend{}) {
		t.Fatalf("retired import: %+v, %v", got, err)
	}
}

func TestAdmissionLedgerImportedSpendRefusesDamage(t *testing.T) {
	for _, name := range []string{"uncounted charge", "usage without a charge", "damaged attempt", "wrong attempt time", "wrong attempt lane", "wrong attempt cost"} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.newUnlimitedLedger()
			f.tickAt(f.wall)
			spend := admission.LegacySpend{Units: 100, At: f.wall.Add(20 * time.Minute)}
			if err := f.l.ImportLegacySpend(2000, spend); err != nil {
				t.Fatal(err)
			}
			var action admission.ActionID
			if name != "uncounted charge" && name != "usage without a charge" {
				_, a := f.admitted(time.Hour)
				action = a.Attempt.ID
			}
			if got, err := f.l.ImportedLegacySpend(); err != nil || got.Units != 100 || !got.At.Equal(spend.At) {
				t.Fatalf("valid import with retained attempts: %+v, %v", got, err)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				switch name {
				case "uncounted charge":
					return putCharge(tx, admission.Charge{At: spend.At, Action: admission.LegacyActionID(spend.At, 3), Lane: admission.LaneGeneral, Cost: 1}, false)
				case "usage without a charge":
					s, err := loadCeilingState(tx)
					if err != nil {
						return err
					}
					s.General.Used++
					return putCeilingState(tx, s)
				case "wrong attempt time", "wrong attempt lane", "wrong attempt cost":
					charge := admission.Charge{At: f.wall, Action: action, Lane: admission.LaneGeneral, Cost: 1}
					key, err := charge.Key()
					if err != nil {
						return err
					}
					if err = tx.Bucket([]byte(admissionChargesBucket)).Delete(key); err != nil {
						return err
					}
					s, err := loadCeilingState(tx)
					if err != nil {
						return err
					}
					s.General.Used--
					if err = putCeilingState(tx, s); err != nil {
						return err
					}
					switch name {
					case "wrong attempt time":
						charge.At = charge.At.Add(time.Nanosecond)
					case "wrong attempt lane":
						charge.Lane = admission.LaneDirect
					case "wrong attempt cost":
						charge.Cost = 2
					}
					return putCharge(tx, charge, true)
				default:
					return tx.Bucket([]byte(admissionAttemptsBucket)).Put([]byte(action), []byte("damaged"))
				}
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if got, err := f.l.ImportedLegacySpend(); !isCorrupt(err) {
				t.Fatalf("damaged import returned %+v, %v", got, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("reading a damaged import changed the ledger")
			}
		})
	}
}

func TestAdmissionLedgerReadsLastLegacyCharge(t *testing.T) {
	f := newLedgerFixture(t)
	f.newUnlimitedLedger()
	spend := admission.LegacySpend{Units: admission.MaxCeiling, At: f.wall.Add(20 * time.Minute)}
	// One general unit and the reserved remainder each have a partial
	// charge, requiring the extra sequence beyond a single lane's bound.
	if err := f.l.ImportLegacySpend(2, spend); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.ImportedLegacySpend(); err != nil || got.Units != admission.MaxCeiling || !got.At.Equal(spend.At) {
		t.Fatalf("last legacy charge: %+v, %v", got, err)
	}
}
