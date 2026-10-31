package store

import (
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// setRecheck is the longest that block work a full set defers sleeps
// before the set is read again: an operator unblock, an expired operator or
// legacy block or a raised limit frees a slot no ledger record names.
const setRecheck = time.Minute

// SetOccupants records the temporary set outside the ledger's effect
// records, as the firewall last showed it: the configured limit, the
// entries admission never evicts (Unclaimed) and the known automatic
// imports (General). Schedules, reservations and wakes then budget block
// work by the free slots it leaves once the ledger's own records are added
// (spec 5.6). nil leaves block work without a slot budget, as an owner
// without a firewall engine runs it.
func (l *AdmissionLedger) SetOccupants(base *admission.SetOccupancy) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if base != nil {
		copied := *base
		base = &copied
	}
	l.set = base
}

// HasChargedWork reports whether a queued candidate that charges the
// ceiling, so takes a set slot, is past its retry wait: the only work a
// read of the set can budget.
func (l *AdmissionLedger) HasChargedWork() (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var found bool
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		clock, err := loadLedgerClock(tx.Bucket([]byte(admissionMetaBucket)))
		if err != nil {
			return err
		}
		q, err := openQueueWith(tx, l.reg, l.Inventory(), clock.Now())
		if err != nil {
			return err
		}
		live, err := q.live()
		for _, lc := range live {
			found = found || (lc.c.State == admission.StateQueued && lc.c.Key.Kind.CeilingCost() > 0 && !q.now.Before(lc.c.NotBefore))
		}
		return err
	})
	return found, err
}

// setBudget is the free slots of each partition in block units; without a
// set it bounds nothing.
type setBudget struct {
	bounded           bool
	general, reserved uint32
}

// slots is the set budget of this transaction: the handle's set with the
// ledger's effect records added.
func (q *queueTx) slots() (setBudget, error) {
	if q.set == nil {
		return setBudget{general: admission.MaxCeiling, reserved: admission.MaxCeiling}, nil
	}
	tally, err := loadEffectTally(q.tx)
	if err != nil {
		return setBudget{}, err
	}
	occ, err := tally.Occupy(*q.set)
	if err != nil {
		return setBudget{}, err
	}
	s := occ.Slots()
	return setBudget{bounded: true, general: slotUnits(s.FreeGeneral), reserved: slotUnits(s.FreeReserved)}, nil
}

// slotUnits is n free slots as block units; no lane budget exceeds the
// ceiling's largest.
func slotUnits(n int) uint32 {
	return uint32(min(max(n, 0), int(admission.MaxCeiling))) // #nosec G115 -- clamped to the ceiling's range.
}

// limit lowers lim's lane budgets to the free slots of the partitions the
// lanes occupy.
func (b setBudget) limit(lim admission.ScheduleLimits) admission.ScheduleLimits {
	lim.General, lim.Reserved = min(lim.General, b.general), min(lim.Reserved, b.reserved)
	return lim
}

// free is the slots a pick on lane may take.
func (b setBudget) free(lane admission.Lane) uint32 {
	if lane == admission.LaneGeneral {
		return b.general
	}
	return b.reserved
}

// soonestEffect is the first future effect expiry. A degraded reading can
// retain past expiries; they must neither spin the timer nor hide a future one.
func soonestEffect(tx *bolt.Tx, now time.Time) (time.Time, bool, error) {
	if err := proveEffects(tx); err != nil {
		return time.Time{}, false, err
	}
	if b := tx.Bucket([]byte(admissionEffectsBucket)); b != nil {
		cur := b.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			rec, err := admission.UnmarshalEffectRecord(k, v)
			if err != nil {
				return time.Time{}, false, err
			}
			if rec.ExpiresAt.After(now) {
				return rec.ExpiresAt, true, nil
			}
		}
	}
	return time.Time{}, false, nil
}
