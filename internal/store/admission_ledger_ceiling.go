package store

import (
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

var ceilingStateKey = []byte("ceiling")

// upgradeLedgerToSchemaThree adds the ceiling to a schema 2 ledger inside
// the opening transaction. Its recent spend is unknown, so its buckets start
// empty rather than full; no charge is invented for earlier reservations.
// The upgrade that completes the chain records the schema.
func upgradeLedgerToSchemaThree(tx *bolt.Tx) error {
	state := tx.Bucket([]byte(admissionQueueStateBucket))
	if state.Get(ceilingStateKey) != nil || state.Bucket(ceilingStateKey) != nil {
		return admission.ErrCorruptRecord
	}
	if _, err := tx.CreateBucket([]byte(admissionChargesBucket)); err != nil {
		return err
	}
	return putCeilingState(tx, admission.CeilingState{})
}

func loadCeilingState(tx *bolt.Tx) (admission.CeilingState, error) {
	raw := tx.Bucket([]byte(admissionQueueStateBucket)).Get(ceilingStateKey)
	if raw == nil {
		return admission.CeilingState{}, admission.ErrCorruptRecord
	}
	return admission.UnmarshalCeilingState(raw)
}

func putCeilingState(tx *bolt.Tx, s admission.CeilingState) error {
	data, err := s.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionQueueStateBucket)).Put(ceilingStateKey, data)
}

// loadCeiling loads the ceiling and proves it against the retained charges:
// they must add up to each lane's recorded usage, and none can have been
// spent after the ceiling's own elapsed time.
func loadCeiling(tx *bolt.Tx) (admission.CeilingState, error) {
	s, err := loadCeilingState(tx)
	if err != nil {
		return s, err
	}
	var general, reserved uint64
	err = tx.Bucket([]byte(admissionChargesBucket)).ForEach(func(k, v []byte) error {
		c, decodeErr := admission.UnmarshalCharge(k, v)
		if decodeErr != nil {
			return decodeErr
		}
		if c.Elapsed > s.Elapsed {
			return admission.ErrCorruptRecord
		}
		if c.Lane == admission.LaneGeneral {
			general += uint64(c.Cost)
		} else {
			reserved += uint64(c.Cost)
		}
		return nil
	})
	if err != nil {
		return s, err
	}
	if general != uint64(s.General.Used) || reserved != uint64(s.Reserved.Used) {
		return s, admission.ErrCorruptRecord
	}
	return s, nil
}

// meterCeiling credits a tick's elapsed time to the ceiling and releases the
// charges that have left the window, oldest first. Keys order charges by
// time and the ledger spends them at non-decreasing elapsed time, so the
// walk stops at the first charge still counted. Stopping can only keep a
// later charge longer, never release one early.
func meterCeiling(tx *bolt.Tx, tick admission.ClockTick) error {
	s, err := loadCeiling(tx)
	if err != nil {
		return err
	}
	if s, err = s.Advance(tick.Elapsed); err != nil {
		return err
	}
	var released [][]byte
	cur := tx.Bucket([]byte(admissionChargesBucket)).Cursor()
	for k, v := cur.First(); k != nil; k, v = cur.Next() {
		c, decodeErr := admission.UnmarshalCharge(k, v)
		if decodeErr != nil {
			return decodeErr
		}
		if !c.Releasable(tick.Now, s.Elapsed) {
			break
		}
		if s, err = s.Release(c.Lane, c.Cost); err != nil {
			return err
		}
		released = append(released, k)
	}
	for _, k := range released {
		if err = tx.Bucket([]byte(admissionChargesBucket)).Delete(k); err != nil {
			return err
		}
	}
	return putCeilingState(tx, s)
}

// SetCeiling records the effective hourly ceiling. The first limit of a new
// ledger fills each bucket to its cap; every later one, including the same
// limit after a restart, only clips saved credit to the new caps.
func (l *AdmissionLedger) SetCeiling(limit uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.update("ceiling", func(tx *bolt.Tx) error {
		s, err := loadCeilingState(tx)
		if err != nil {
			return err
		}
		if s, err = s.SetLimit(limit); err != nil {
			return err
		}
		return putCeilingState(tx, s)
	})
}

// Ceiling is the committed ceiling state.
func (l *AdmissionLedger) Ceiling() (admission.CeilingState, error) {
	var s admission.CeilingState
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		s, err = loadCeilingState(tx)
		return err
	})
	return s, err
}

// laneFits checks that a queued candidate may be reserved on lane. Any
// candidate may use the general lane. A reserved lane is rechecked against
// the candidate's assessment at now, since the pick was made in an earlier
// transaction: direct compromise evidence has only the direct turn and
// corroboration only the corroborated one.
func (l *AdmissionLedger) laneFits(tx *bolt.Tx, lc liveCandidate, lane admission.Lane, now time.Time) error {
	switch {
	case !lane.Valid():
		return refusal(admission.ReasonInvalid, "reservation names no lane")
	case lane == admission.LaneGeneral:
		return nil
	}
	q, err := l.openQueue(tx, now)
	if err != nil {
		return err
	}
	a, reason, err := q.check(lc, true)
	switch {
	case err != nil:
		return err
	case reason != 0:
		return refusal(reason, "candidate no longer qualifies for a response")
	case lane == admission.LaneDirect && !a.DirectC3, lane == admission.LaneCorroborated && !a.Corroborated:
		return admission.ErrLaneIneligible
	}
	return nil
}

// chargeTx spends cost units of lane's ceiling budget for an attempt and
// records the charge, in the reservation's own transaction.
func chargeTx(tx *bolt.Tx, now time.Time, action admission.ActionID, lane admission.Lane, cost uint32) error {
	s, err := loadCeilingState(tx)
	if err != nil {
		return err
	}
	if s, err = s.Charge(lane, cost); err != nil {
		return err
	}
	c := admission.Charge{At: now, Action: action, Lane: lane, Cost: cost, Elapsed: s.Elapsed}
	key, err := c.Key()
	if err != nil {
		return err
	}
	data, err := c.MarshalBinary()
	if err != nil {
		return err
	}
	charges := tx.Bucket([]byte(admissionChargesBucket))
	// Overwriting a stored charge would leave usage the retained charges no
	// longer prove, and the next tick would refuse it.
	if charges.Get(key) != nil {
		return admission.ErrCorruptRecord
	}
	if err = charges.Put(key, data); err != nil {
		return err
	}
	return putCeilingState(tx, s)
}

// loadCharges is every retained charge in key order, oldest first.
func loadCharges(tx *bolt.Tx) ([]admission.Charge, error) {
	var out []admission.Charge
	err := tx.Bucket([]byte(admissionChargesBucket)).ForEach(func(k, v []byte) error {
		c, err := admission.UnmarshalCharge(k, v)
		if err != nil {
			return err
		}
		out = append(out, c)
		return nil
	})
	return out, err
}
