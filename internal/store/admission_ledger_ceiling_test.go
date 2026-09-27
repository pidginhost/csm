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
	if err := f.l.SetCeiling(2000); err != nil {
		t.Fatal(err)
	}
	s, err := f.l.Ceiling()
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
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return putCharge(tx, f.ledgerCharge(dated, 1, admission.LaneGeneral, f.ceilingState().Elapsed), true)
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
	spent := f.ceilingState()
	f.tickAt(f.wall)
	if got := f.ceilingState(); got != spent {
		t.Fatalf("same elapsed interval credited twice: %+v", got)
	}
}
