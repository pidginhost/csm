package admission

import (
	"slices"
	"time"
)

// EvictionVictim is a verified automatic block that strictly higher work
// may evict when the set has no free slot for it (spec 5.6).
type EvictionVictim struct {
	Action    ActionID
	Tier      Tier
	Partition Partition
	ExpiresAt time.Time
}

// victimOrder is the eviction order: the lowest tier first, then the
// earliest absolute expiry, then the lowest action ID.
func victimOrder(a, b EvictionVictim) int {
	switch {
	case a.Tier.Less(b.Tier):
		return -1
	case b.Tier.Less(a.Tier):
		return 1
	}
	if c := a.ExpiresAt.Compare(b.ExpiresAt); c != 0 {
		return c
	}
	switch {
	case a.Action < b.Action:
		return -1
	case a.Action > b.Action:
		return 1
	}
	return 0
}

// SlotDemand is what a pick asks of the set.
type SlotDemand struct {
	Tier Tier
	// Cost is the set slots it takes: its ceiling cost.
	Cost uint32
	// Evicts is set for one-unit block_ip work, the only work that may
	// evict (spec 5.6, one victim per charged unit).
	Evicts bool
	// Reserved is set for work eligible for a reserved lane.
	Reserved bool
}

// SlotLimits bound block work by the temporary set: the free slots of each
// partition and the victims strictly higher work may evict. A nil
// *SlotLimits bounds nothing. Take consumes what it grants; Room only asks.
type SlotLimits struct {
	freeGeneral, freeReserved uint32
	// victims is sorted in victimOrder and holds what is still free to take.
	victims []EvictionVictim
}

// NewSlotLimits holds the free slots of each partition and a sorted copy of
// the victim pool.
func NewSlotLimits(freeGeneral, freeReserved uint32, victims []EvictionVictim) *SlotLimits {
	pool := slices.Clone(victims)
	slices.SortFunc(pool, victimOrder)
	return &SlotLimits{freeGeneral: freeGeneral, freeReserved: freeReserved, victims: pool}
}

// Clone is an independent copy; nil stays nil.
func (s *SlotLimits) Clone() *SlotLimits {
	if s == nil {
		return nil
	}
	return &SlotLimits{freeGeneral: s.freeGeneral, freeReserved: s.freeReserved, victims: slices.Clone(s.victims)}
}

// Budget bounds a lane by its free slots or, under pressure, its victims.
// Per-lane readiness and Take decide whether each pick can use that room.
func (s *SlotLimits) Budget(lane Lane) uint32 {
	if s == nil {
		return MaxCeiling
	}
	free, n := s.freeGeneral, uint32(0)
	if PartitionOf(lane) == PartitionReserved {
		free = s.freeReserved
	}
	if free > 0 || (PartitionOf(lane) == PartitionReserved && s.freeGeneral > 0) {
		return min(free, MaxCeiling)
	}
	for _, v := range s.victims {
		if PartitionOf(lane) == PartitionReserved || v.Partition == PartitionGeneral {
			n++
		}
	}
	return min(free+n, MaxCeiling)
}

// Room reports how work d finds room on lane: a free slot of the lane's
// partition (a zero victim) or, under pressure, the first victim in
// eviction order that d strictly outranks. Pressure means no free slot
// for d on any lane it may use: general work never takes a reserved slot
// or evicts a reserved entry, and reserved work may evict in either
// partition. ok is false when d must wait.
func (s *SlotLimits) Room(lane Lane, d SlotDemand) (EvictionVictim, bool) {
	i, ok := s.room(lane, d)
	if i < 0 {
		return EvictionVictim{}, ok
	}
	return s.victims[i], ok
}

// Take is Room that consumes what it grants.
func (s *SlotLimits) Take(lane Lane, d SlotDemand) (EvictionVictim, bool) {
	i, ok := s.room(lane, d)
	switch {
	case !ok || s == nil:
		return EvictionVictim{}, ok
	case i >= 0:
		v := s.victims[i]
		s.victims = slices.Delete(s.victims, i, i+1)
		return v, true
	case PartitionOf(lane) == PartitionReserved:
		s.freeReserved -= d.Cost
	default:
		s.freeGeneral -= d.Cost
	}
	return EvictionVictim{}, true
}

func (s *SlotLimits) room(lane Lane, d SlotDemand) (int, bool) {
	if s == nil || d.Cost == 0 {
		return -1, true
	}
	reserved := PartitionOf(lane) == PartitionReserved
	own, other := s.freeGeneral, s.freeReserved
	if reserved {
		own, other = other, own
	}
	if d.Cost <= own {
		return -1, true
	}
	// A free slot another lane of the work could take is no pressure.
	if (reserved || d.Reserved) && d.Cost <= other {
		return -1, false
	}
	if !d.Evicts || d.Cost != 1 {
		return -1, false
	}
	for i, v := range s.victims {
		if v.Tier.Less(d.Tier) && (reserved || v.Partition == PartitionGeneral) {
			return i, true
		}
	}
	return -1, false
}
