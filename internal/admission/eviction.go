package admission

import (
	"slices"
	"time"
)

// EvictionVictim is a verified automatic block that strictly higher work
// may evict when the set has no free slot for it (spec 5.6): an effect
// record or an import, whose Action is its effect name.
type EvictionVictim struct {
	Action    ActionID
	Target    Target
	Tier      Tier
	Partition Partition
	ExpiresAt time.Time
}

// ImportTier is the tier of an import, a known automatic block an older
// producer wrote with explicit provenance (spec 6): (C2, High).
var ImportTier = Tier{Class: ClassC2, Severity: SeverityHigh}

// Imported reports whether v is an import as the engine's list hands it
// over: an import name, an address, the import tier, the general
// partition it is counted in and an expiry after the epoch.
func (v EvictionVictim) Imported() bool {
	ends, ok := unixNano(v.ExpiresAt)
	return ImportedVictim(v.Action) && ValidateKindTarget(KindBlockIP, v.Target) == nil && v.Tier == ImportTier &&
		v.Partition == PartitionGeneral && ok && ends > 0
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
	// Target is the work's address; the block of that address is never
	// its victim.
	Target Target
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

// Limits is the slot budget of o, the one rule admission and its forecast
// share (spec 5.6): each partition's free slots and, once the general
// partition is full and the set is not overfull, the victims pool returns,
// less those of an overfull partition. pool is read only then.
func (o SetOccupancy) Limits(pool func() ([]EvictionVictim, error)) (*SlotLimits, error) {
	s := o.Slots()
	var victims []EvictionVictim
	if s.FreeGeneral == 0 && o.General+o.Reserved <= s.Available {
		var err error
		if victims, err = pool(); err != nil {
			return nil, err
		}
	}
	victims = slices.DeleteFunc(victims, func(v EvictionVictim) bool {
		return (v.Partition == PartitionGeneral && o.General > s.General) || (v.Partition == PartitionReserved && o.Reserved > s.Reserved)
	})
	return NewSlotLimits(slotUnits(s.FreeGeneral), slotUnits(s.FreeReserved), victims), nil
}

// slotUnits is n free slots as block units; no lane budget exceeds the
// ceiling's largest.
func slotUnits(n int) uint32 {
	return uint32(min(max(n, 0), int(MaxCeiling))) // #nosec G115 -- clamped to the ceiling's range.
}

// Clone is an independent copy; nil stays nil.
func (s *SlotLimits) Clone() *SlotLimits {
	if s == nil {
		return nil
	}
	return &SlotLimits{freeGeneral: s.freeGeneral, freeReserved: s.freeReserved, victims: slices.Clone(s.victims)}
}

// Budget bounds a lane by its free slots or, under pressure, its victims
// below the highest valid tier, which no work may evict.
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
	highest := Tier{Class: ClassC3, Severity: SeverityCritical}
	for _, v := range s.victims {
		if !v.Tier.Less(highest) {
			break
		}
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
		if v.Tier.Less(d.Tier) && v.Target != d.Target && (reserved || v.Partition == PartitionGeneral) {
			return i, true
		}
	}
	return -1, false
}
