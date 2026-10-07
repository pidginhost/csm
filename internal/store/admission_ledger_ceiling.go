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

// ImportLegacySpend takes a new ledger's first limit together with the
// legacy hourly counter's spend, in one transaction (spec 5.4 migration).
// A ledger that already has a limit refuses: its import is done, and a
// restart or rerun cannot create fresh credit.
func (l *AdmissionLedger) ImportLegacySpend(limit uint32, spend admission.LegacySpend) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.update("ceiling", func(tx *bolt.Tx) error {
		s, err := loadCeilingState(tx)
		if err != nil {
			return err
		}
		next, charges, err := s.Import(limit, spend)
		if err != nil {
			return err
		}
		bucket := tx.Bucket([]byte(admissionChargesBucket))
		for _, c := range charges {
			key, err := c.Key()
			if err != nil {
				return err
			}
			data, err := c.MarshalBinary()
			if err != nil {
				return err
			}
			if bucket.Get(key) != nil {
				return admission.ErrCorruptRecord
			}
			if err = bucket.Put(key, data); err != nil {
				return err
			}
		}
		return putCeilingState(tx, next)
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
func laneFits(q *queueTx, lc liveCandidate, lane admission.Lane) error {
	switch {
	case !lane.Valid():
		return refusal(admission.ReasonInvalid, "reservation names no lane")
	case lane == admission.LaneGeneral:
		return nil
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

// ImportedLegacySpend reads the retained legacy charges for startup status.
// A charge of a retained attempt must match it. A charge whose attempt has
// retired is no legacy spend: after a reboot a charge waits for its
// remaining elapsed time, while history retires by wall time.
func (l *AdmissionLedger) ImportedLegacySpend() (admission.LegacySpend, error) {
	var spend admission.LegacySpend
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		if _, err := loadCeiling(tx); err != nil {
			return err
		}
		charges, err := loadCharges(tx)
		if err != nil {
			return err
		}
		var idsAt time.Time
		ids := make(map[admission.ActionID]bool)
		for _, c := range charges {
			if tx.Bucket([]byte(admissionAttemptsBucket)).Get([]byte(c.Action)) != nil {
				a, err := loadAttempt(tx, c.Action)
				if err != nil {
					return corruptRecord(err)
				}
				candidate, err := loadCandidate(tx, a.Attempt.Candidate)
				if err != nil || !c.At.Equal(a.Reserved) || c.Lane != a.Lane || c.Cost != candidate.Key.Kind.CeilingCost() {
					return admission.ErrCorruptRecord
				}
				continue
			}
			if !c.At.Equal(idsAt) {
				// Charges are time-ordered; prior timestamps never recur.
				clear(ids)
				for seq := uint32(1); seq <= (admission.MaxCeiling+admission.MaxMemberCost-1)/admission.MaxMemberCost+1; seq++ {
					ids[admission.LegacyActionID(c.At, seq)] = true
				}
				idsAt = c.At
			}
			if !ids[c.Action] {
				continue
			}
			// One import charged every legacy unit at one time.
			if spend.Units != 0 && !spend.At.Equal(c.At) {
				return admission.ErrCorruptRecord
			}
			spend.At = c.At
			spend.Units += c.Cost
		}
		return nil
	})
	if err != nil {
		return admission.LegacySpend{}, err
	}
	return spend, err
}
