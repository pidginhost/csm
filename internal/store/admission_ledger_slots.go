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

// SetImports records the known automatic imports the firewall last listed
// (spec 6): (C2, High) victims in the general partition with no record of
// their own, which SetOccupants counts as General. Entries that are not
// such an import are dropped. A block that claims one names it in its own
// record until its outcome.
func (l *AdmissionLedger) SetImports(imports []admission.EvictionVictim) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.imports = nil
	for _, v := range imports {
		if v.Imported() {
			l.imports = append(l.imports, v)
		}
	}
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
// verified records and imports strictly higher work may evict once the
// general partition is full (no work evicts while it has a free slot). A
// live ledger on a trusted clock also shares each partition among its
// scopes, so fresh work may rotate an equal-tier record whose hold passed
// (spec 5.6).
func (q *queueTx) slots() (*admission.SlotLimits, error) {
	if q.set == nil {
		return nil, nil
	}
	tally, err := loadEffectTally(q.tx)
	if err != nil {
		return nil, err
	}
	base := *q.set
	// The bounded list can omit imports, but every listed import still
	// occupies a general slot. Leave invalid counts for tally validation.
	if base.General >= 0 {
		base.General = max(base.General, len(q.imports))
	}
	occ, err := tally.Occupy(base)
	if err != nil {
		return nil, err
	}
	var holding map[admission.Partition]map[string]int
	slots, err := occ.Limits(func() ([]admission.EvictionVictim, error) {
		rotates, holdErr := q.holdTest()
		if holdErr != nil {
			return nil, holdErr
		}
		pool, scopes, poolErr := victimPool(q.tx, q.now, rotates, q.imports)
		if rotates != nil {
			holding = scopes
		}
		return pool, poolErr
	})
	if err == nil && holding != nil {
		slots.Share(holding, q.waiting, q.state.SetCursors)
		q.shared = true
	}
	return slots, err
}

// waitingScopes are the scopes of queued work that would hold a set
// slot, by the partitions it may occupy: general, and reserved too for
// work eligible for a reserved lane. Such work shares the set with the
// scopes holding it (spec 5.6: active scopes include eligible waiting
// work); a retry's wait does not end its claim.
func waitingScopes(items []admission.ScheduleItem, byID map[admission.CandidateID]liveCandidate) map[admission.Partition][]string {
	out := map[admission.Partition][]string{}
	for _, it := range items {
		if !demandOf(it, byID[it.ID]).Evicts {
			continue
		}
		out[admission.PartitionGeneral] = append(out[admission.PartitionGeneral], it.Scope)
		if reservedLane(it) != 0 {
			out[admission.PartitionReserved] = append(out[admission.PartitionReserved], it.Scope)
		}
	}
	for p := range out {
		slices.Sort(out[p])
		out[p] = slices.Compact(out[p])
	}
	return out
}

// holdTest reports whether a record's rotation hold passed: nil, so no
// record rotates, before the live start or on a degraded reading (spec
// 5.4: wall time alone proves nothing then).
func (q *queueTx) holdTest() (func(admission.EffectRecord) bool, error) {
	if !q.started || q.degraded {
		return nil, nil
	}
	ceiling, err := loadCeilingState(q.tx)
	if err != nil {
		return nil, err
	}
	return func(rec admission.EffectRecord) bool { return rec.HoldPassed(q.now, ceiling.Elapsed) }, nil
}

// victimPool is what strictly higher work may evict and fresh equal-tier
// work may rotate (spec 5.6): records verified, holding their slot and
// claimed by no pending block, each with its scope and application and
// rotatable when rotates passes it, and the unexpired imports no block's
// record names. holding counts the slots each scope's unexpired,
// unclaimed records hold in each partition, pending ones included. The
// full-set path walks the records once; free-slot admission skips it.
func victimPool(tx *bolt.Tx, now time.Time, rotates func(admission.EffectRecord) bool, imports []admission.EvictionVictim) ([]admission.EvictionVictim, map[admission.Partition]map[string]int, error) {
	var pool []admission.EvictionVictim
	holding := map[admission.Partition]map[string]int{}
	claimed := map[admission.ActionID]bool{}
	if b := tx.Bucket([]byte(admissionEffectsBucket)); b != nil {
		err := b.ForEach(func(k, v []byte) error {
			rec, err := admission.UnmarshalEffectRecord(k, v)
			if err != nil {
				return err
			}
			if rec.Victim.Imported() {
				claimed[rec.Victim.Action] = true
			}
			if !rec.Holds() || rec.EvictedBy != "" || !rec.ExpiresAt.After(now) {
				return nil
			}
			if holding[rec.Partition] == nil {
				holding[rec.Partition] = map[string]int{}
			}
			holding[rec.Partition][rec.Scope]++
			if rec.Verified() {
				pool = append(pool, admission.EvictionVictim{Action: rec.Action, Target: rec.Target, Tier: rec.Tier, Partition: rec.Partition, ExpiresAt: rec.ExpiresAt,
					Scope: rec.Scope, Applied: rec.Applied, Rotatable: rotates != nil && rotates(rec)})
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	for _, v := range imports {
		if !claimed[v.Action] && v.ExpiresAt.After(now) {
			pool = append(pool, v)
		}
	}
	return pool, holding, nil
}

// fresh reports whether c's episode has had no verified response, the
// only work that may rotate an equal-tier block (spec 5.2). Work whose
// episode row is missing or names another episode is not fresh: an
// unknown history never proves a new episode.
func (q *queueTx) fresh(c admission.Candidate) (bool, error) {
	if !q.started {
		return false, nil
	}
	return freshEpisode(q.tx, c)
}

// freshEpisode reports whether c is block_ip work whose target's episode
// row names its episode and records no verified response.
func freshEpisode(tx *bolt.Tx, c admission.Candidate) (bool, error) {
	if c.Key.Kind != admission.KindBlockIP {
		return false, nil
	}
	e, found, err := loadEpisode(tx, c.Key.Target.Key())
	return found && e.ID == c.Key.Episode && e.Verified.IsZero(), err
}

// Fresh reports whether c's episode row lets it rotate an equal-tier
// block as a live ledger decides it (spec 5.2), on any ledger: a dry-run
// forecast asks it for its picks.
func (l *AdmissionLedger) Fresh(c admission.Candidate) (bool, error) {
	var fresh bool
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		fresh, err = freshEpisode(tx, c)
		return err
	})
	return fresh, err
}

// markFresh notes which of the live candidates byID are fresh. Only a
// shared set needs it: nothing rotates otherwise.
func (q *queueTx) markFresh(byID map[admission.CandidateID]liveCandidate) error {
	if !q.shared {
		return nil
	}
	for id, lc := range byID {
		var err error
		if lc.fresh, err = q.fresh(lc.c); err != nil {
			return err
		}
		byID[id] = lc
	}
	return nil
}

// limitBySlots lowers lane budgets to free slots or victims under
// pressure; readiness and contention checks decide each pick's fit.
func limitBySlots(lim admission.ScheduleLimits, slots *admission.SlotLimits) admission.ScheduleLimits {
	lim.General, lim.Reserved = min(lim.General, slots.Budget(admission.LaneGeneral)), min(lim.Reserved, slots.Budget(admission.LaneDirect))
	return lim
}

// demandOf is what schedule item it of candidate lc asks of the set: only
// one-unit block_ip work may evict, never the block of its own address,
// and only fresh work may rotate.
func demandOf(it admission.ScheduleItem, lc liveCandidate) admission.SlotDemand {
	return admission.SlotDemand{Tier: it.Tier, Cost: it.CeilingCost, Evicts: lc.c.Key.Kind == admission.KindBlockIP && it.CeilingCost == 1,
		Reserved: it.Direct || it.Corroborated, Target: lc.c.Key.Target, Scope: it.Scope, Fresh: lc.fresh}
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
