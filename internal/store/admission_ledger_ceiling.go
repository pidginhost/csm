package store

import (
	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

var ceilingStateKey = []byte("ceiling")

// upgradeLedgerToSchemaThree adds the ceiling to a schema 2 ledger inside
// the opening transaction. Its recent spend is unknown, so its buckets start
// empty rather than full; no charge is invented for earlier reservations.
func upgradeLedgerToSchemaThree(tx *bolt.Tx) error {
	state := tx.Bucket([]byte(admissionQueueStateBucket))
	if state.Get(ceilingStateKey) != nil || state.Bucket(ceilingStateKey) != nil {
		return admission.ErrCorruptRecord
	}
	if _, err := tx.CreateBucket([]byte(admissionChargesBucket)); err != nil {
		return err
	}
	if err := putCeilingState(tx, admission.CeilingState{}); err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaVersion})
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
