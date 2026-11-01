package store

import (
	"slices"
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

// slots is the set budget of this transaction: nil without a set, else
// the free slots the handle's set and the ledger's records leave, with the
// verified records strictly higher work may evict once the general
// partition is full (no work evicts while it has a free slot).
func (q *queueTx) slots() (*admission.SlotLimits, error) {
	if q.set == nil {
		return nil, nil
	}
	tally, err := loadEffectTally(q.tx)
	if err != nil {
		return nil, err
	}
	occ, err := tally.Occupy(*q.set)
	if err != nil {
		return nil, err
	}
	s := occ.Slots()
	var pool []admission.EvictionVictim
	if s.FreeGeneral == 0 && occ.General+occ.Reserved <= s.Available {
		if pool, err = victimPool(q.tx, q.now); err != nil {
			return nil, err
		}
	}
	pool = slices.DeleteFunc(pool, func(v admission.EvictionVictim) bool {
		return (v.Partition == admission.PartitionGeneral && occ.General > s.General) ||
			(v.Partition == admission.PartitionReserved && occ.Reserved > s.Reserved)
	})
	return admission.NewSlotLimits(slotUnits(s.FreeGeneral), slotUnits(s.FreeReserved), pool), nil
}

// victimPool is the records strictly higher work may evict (spec 5.6):
// verified, holding their slot and claimed by no pending block.
// The full-set path walks the records once; free-slot admission skips it.
func victimPool(tx *bolt.Tx, now time.Time) ([]admission.EvictionVictim, error) {
	b := tx.Bucket([]byte(admissionEffectsBucket))
	if b == nil {
		return nil, nil
	}
	var pool []admission.EvictionVictim
	err := b.ForEach(func(k, v []byte) error {
		rec, err := admission.UnmarshalEffectRecord(k, v)
		if err == nil && rec.Verified() && rec.Holds() && rec.EvictedBy == "" && rec.ExpiresAt.After(now) {
			pool = append(pool, admission.EvictionVictim{Action: rec.Action, Target: rec.Target, Tier: rec.Tier, Partition: rec.Partition, ExpiresAt: rec.ExpiresAt})
		}
		return err
	})
	return pool, err
}

// slotUnits is n free slots as block units; no lane budget exceeds the
// ceiling's largest.
func slotUnits(n int) uint32 {
	return uint32(min(max(n, 0), int(admission.MaxCeiling))) // #nosec G115 -- clamped to the ceiling's range.
}

// limitBySlots lowers lane budgets to free slots or victims under
// pressure; readiness and contention checks decide each pick's fit.
func limitBySlots(lim admission.ScheduleLimits, slots *admission.SlotLimits) admission.ScheduleLimits {
	lim.General, lim.Reserved = min(lim.General, slots.Budget(admission.LaneGeneral)), min(lim.Reserved, slots.Budget(admission.LaneDirect))
	return lim
}

// demandOf is what schedule item it of candidate lc asks of the set: only
// one-unit block_ip work may evict, never the block of its own address.
func demandOf(it admission.ScheduleItem, lc liveCandidate) admission.SlotDemand {
	return admission.SlotDemand{Tier: it.Tier, Cost: it.CeilingCost, Evicts: lc.c.Key.Kind == admission.KindBlockIP && it.CeilingCost == 1,
		Reserved: it.Direct || it.Corroborated, Target: lc.c.Key.Target}
}

// reservedLane is the reserved lane item it is eligible for; zero for
// general-only work.
func reservedLane(it admission.ScheduleItem) admission.Lane {
	switch {
	case it.Direct:
		return admission.LaneDirect
	case it.Corroborated:
		return admission.LaneCorroborated
	}
	return 0
}

// roomOn reports whether item it finds room in slots on its general lane
// and on its reserved lane, if any.
func roomOn(slots *admission.SlotLimits, it admission.ScheduleItem, lc liveCandidate) (general, reserved bool) {
	d := demandOf(it, lc)
	_, general = slots.Room(admission.LaneGeneral, d)
	if lane := reservedLane(it); lane != 0 {
		_, reserved = slots.Room(lane, d)
	}
	return general, reserved
}

// slotReady refines lane readiness without changing the overall Ready
// control: slot pressure preserves saved turns, while backoff releases
// a saved ceiling turn through the scheduler's existing rule.
func slotReady(items []admission.ScheduleItem, byID map[admission.CandidateID]liveCandidate, slots *admission.SlotLimits) []admission.ScheduleItem {
	out := slices.Clone(items)
	for i := range out {
		general, reserved := roomOn(slots, out[i], byID[out[i].ID])
		out[i].BlockedGeneral, out[i].BlockedReserved = !general, !reserved
	}
	return out
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
			if rec.Holds() && rec.ExpiresAt.After(now) {
				return rec.ExpiresAt, true, nil
			}
		}
	}
	return time.Time{}, false, nil
}
