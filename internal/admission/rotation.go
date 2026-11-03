package admission

import (
	"maps"
	"slices"
	"sort"
	"time"
)

// RotationHold is how long a verified automatic block keeps its slot
// before equal-tier rotation may take it, on both wall and elapsed
// admission time (spec 5.6).
const RotationHold = 30 * time.Minute

// RotationHoldPassed reports whether a block applied at admission time
// applied, when the ceiling's elapsed time read from, has kept its slot
// for RotationHold on both clocks at admission time now with elapsed, as
// a charge's window does. Downtime never counts, so a restart cannot
// shorten a hold.
func RotationHoldPassed(applied time.Time, from time.Duration, now time.Time, elapsed time.Duration) bool {
	return !now.Before(applied.Add(RotationHold)) && elapsed-from >= RotationHold
}

// HoldPassed reports whether e's rotation hold has passed at admission
// time now with the ceiling's elapsed time elapsed: its application is
// verified and RotationHoldPassed holds since.
func (e EffectRecord) HoldPassed(now time.Time, elapsed time.Duration) bool {
	return e.Verified() && RotationHoldPassed(e.Applied, e.Elapsed, now, elapsed)
}

// fairShare is the integer share rule of spec 5.6, the same for queue
// positions and set slots: capacity split evenly over the scopes, and the
// remainder one each to the scopes after the cursor in rotation order.
type fairShare struct {
	// keys are the scopes in rotation order, from the one after the cursor.
	keys     []string
	rank     map[string]int
	capacity int
}

// newFairShare shares capacity among keys, sorted, unique and not empty.
func newFairShare(keys []string, cursor string, capacity int) fairShare {
	n := len(keys)
	start := sort.SearchStrings(keys, cursor)
	if start < n && keys[start] == cursor {
		start++
	}
	start %= n
	f := fairShare{keys: make([]string, n), rank: make(map[string]int, n), capacity: capacity}
	for r := range n {
		f.keys[r] = keys[(start+r)%n]
		f.rank[f.keys[r]] = r
	}
	return f
}

// of is the share of key, one of the shared keys.
func (f fairShare) of(key string) int {
	n := len(f.keys)
	if f.rank[key] < f.capacity%n {
		return f.capacity/n + 1
	}
	return f.capacity / n
}

// first is the scope after the cursor: where the cursor moves next.
func (f fairShare) first() string { return f.keys[0] }

// setShares is how the scopes of each partition share it under pressure.
type setShares struct {
	holding [partitionEnd]map[string]int
	waiting [partitionEnd][]string
	cursor  [partitionEnd]string
}

func (sh *setShares) clone() *setShares {
	if sh == nil {
		return nil
	}
	out := *sh
	for p := range out.holding {
		out.holding[p] = maps.Clone(sh.holding[p])
		out.waiting[p] = slices.Clone(sh.waiting[p])
	}
	return &out
}

// active is the sorted scopes of partition p: those holding a slot, those
// waiting for one and extra, if not empty.
func (sh *setShares) active(p Partition, extra string) []string {
	var keys []string
	for k, n := range sh.holding[p] {
		if n > 0 {
			keys = append(keys, k)
		}
	}
	keys = append(keys, sh.waiting[p]...)
	if extra != "" {
		keys = append(keys, extra)
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}

// move counts a slot of partition p for scope taken from victim, which
// leaves its own scope.
func (sh *setShares) move(p Partition, scope string, victim EvictionVictim) {
	if sh == nil {
		return
	}
	if scope != "" {
		if sh.holding[p] == nil {
			sh.holding[p] = map[string]int{}
		}
		sh.holding[p][scope]++
	}
	if victim.Scope != "" && sh.holding[victim.Partition][victim.Scope] > 0 {
		sh.holding[victim.Partition][victim.Scope]--
	}
}

// Share lets fresh work rotate equal-tier blocks out of a full partition
// (spec 5.6). holding is the slots each scope's unclaimed blocks hold in
// each partition, waiting the scopes with work waiting for a slot there,
// and cursors the partitions' persisted remainder cursors. A partition is
// shared among its active scopes, those holding or waiting and the
// requester. Without it no work rotates.
func (s *SlotLimits) Share(holding map[Partition]map[string]int, waiting map[Partition][]string, cursors QueueCursors) {
	if s == nil {
		return
	}
	sh := &setShares{}
	for _, p := range []Partition{PartitionGeneral, PartitionReserved} {
		sh.holding[p] = maps.Clone(holding[p])
		sh.waiting[p] = slices.Clone(waiting[p])
	}
	sh.cursor[PartitionGeneral], sh.cursor[PartitionReserved] = cursors.General, cursors.Reserved
	s.shares = sh
}

// Advance moves each partition's remainder cursor to the first active
// scope after it and returns the cursors; a partition without an active
// scope keeps its cursor. A schedule cycle advances them once, so scopes
// that outnumber the slots take turns at the remainder (spec 5.6).
func (s *SlotLimits) Advance() QueueCursors {
	if s == nil || s.shares == nil {
		return QueueCursors{}
	}
	sh := s.shares
	for _, p := range []Partition{PartitionGeneral, PartitionReserved} {
		if keys := sh.active(p, ""); len(keys) > 0 {
			sh.cursor[p] = newFairShare(keys, sh.cursor[p], 0).first()
		}
	}
	return QueueCursors{General: sh.cursor[PartitionGeneral], Reserved: sh.cursor[PartitionReserved]}
}

// rotation is the index of the block fresh work d may rotate out of its
// lane's partition, or -1 (spec 5.6). Only verified blocks of tier
// exactly d.Tier and of a scope are candidates. The scope comes first:
// zero share waits; at or over a positive share d rotates only its own
// blocks; below it, d reclaims only the greatest over-share borrowing,
// ties in cursor order, and never
// takes a scope below its share. Then the oldest application, then the
// lowest action, among the chosen scope's blocks whose hold passed; none
// means d waits.
func (s *SlotLimits) rotation(lane Lane, d SlotDemand) int {
	p := PartitionOf(lane)
	if s.shares == nil || !d.Fresh || d.Scope == "" || !p.Valid() {
		return -1
	}
	sh := s.shares
	candidate := func(v EvictionVictim) bool { return rotationCandidate(p, d, v) }
	// The scopes with a candidate, whatever its age: one pass, not one per
	// scope.
	listed := map[string]bool{}
	for _, v := range s.victims {
		if candidate(v) {
			listed[v.Scope] = true
		}
	}
	share := newFairShare(sh.active(p, d.Scope), sh.cursor[p], s.size[p])
	if share.of(d.Scope) == 0 {
		return -1
	}
	scope := d.Scope
	if sh.holding[p][d.Scope] < share.of(d.Scope) {
		scope = ""
		best := 0
		for _, k := range share.keys {
			if k == d.Scope || !listed[k] {
				continue
			}
			if excess := sh.holding[p][k] - share.of(k); excess > best {
				scope, best = k, excess
			}
		}
		if scope == "" {
			return -1
		}
	}
	pick := -1
	for i, v := range s.victims {
		if !candidate(v) || v.Scope != scope || !v.Rotatable {
			continue
		}
		if pick < 0 || v.Applied.Before(s.victims[pick].Applied) ||
			(v.Applied.Equal(s.victims[pick].Applied) && v.Action < s.victims[pick].Action) {
			pick = i
		}
	}
	return pick
}

// rotationCandidate reports whether v is a block of partition p that
// rotation could give work d: a scoped block, never an import, of
// exactly d's tier at another address.
func rotationCandidate(p Partition, d SlotDemand, v EvictionVictim) bool {
	return v.Partition == p && v.Tier == d.Tier && v.Target != d.Target && v.Scope != ""
}

// EqualTier reports whether lane's partition holds a block rotation could
// give one-unit block work d once the block's hold, d's freshness and the
// shares allow it. Work that finds no room while one does waits on an
// equal-tier block (spec 5.17).
func (s *SlotLimits) EqualTier(lane Lane, d SlotDemand) bool {
	if s == nil || !d.Evicts || d.Cost != 1 {
		return false
	}
	p := PartitionOf(lane)
	return slices.ContainsFunc(s.victims, func(v EvictionVictim) bool { return rotationCandidate(p, d, v) })
}
