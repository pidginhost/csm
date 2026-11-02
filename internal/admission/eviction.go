package admission

import (
	"slices"
	"time"
)

// EvictionVictim is a verified automatic block that strictly higher work
// may evict when the set has no free slot for it (spec 5.6): an effect
// record or an import, whose Action is its effect name. Fresh work of the
// same tier may rotate a record out once its hold passed.
type EvictionVictim struct {
	Action    ActionID
	Target    Target
	Tier      Tier
	Partition Partition
	ExpiresAt time.Time
	// Scope is the fairness scope of a record's block and Applied when its
	// application was verified; an import has neither.
	Scope   string
	Applied time.Time
	// Rotatable is set for a record whose rotation hold passed on a
	// trusted clock: equal-tier rotation may take only such a block.
	Rotatable bool
}

// ImportTier is the tier of an import, a known automatic block an older
// producer wrote with explicit provenance (spec 6): (C2, High).
var ImportTier = Tier{Class: ClassC2, Severity: SeverityHigh}

// Imported reports whether v is an import as the engine's list hands it
// over: an import name, an address, the import tier, the general
// partition it is counted in and an expiry after the epoch, with no scope,
// application or rotation: an import never rotates (spec 6).
func (v EvictionVictim) Imported() bool {
	ends, ok := unixNano(v.ExpiresAt)
	return ImportedVictim(v.Action) && ValidateKindTarget(KindBlockIP, v.Target) == nil && v.Tier == ImportTier &&
		v.Partition == PartitionGeneral && ok && ends > 0 && v.Scope == "" && v.Applied.IsZero() && !v.Rotatable
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
	// Scope is the work's fairness scope; Fresh is set while its episode
	// has had no verified response, the only work that may rotate an
	// equal-tier block (spec 5.2, 5.6).
	Scope string
	Fresh bool
}

// SlotLimits bound block work by the temporary set: the free slots of each
// partition, the victims strictly higher work may evict and, once Share
// sets the scopes' shares, the equal-tier blocks fresh work may rotate. A
// nil *SlotLimits bounds nothing. Take consumes what it grants; Room only
// asks.
type SlotLimits struct {
	freeGeneral, freeReserved uint32
	// victims is sorted in victimOrder and holds what is still free to take.
	victims []EvictionVictim
	// size is each partition's slots, which its scopes share; shares, once
	// set, lets fresh work rotate equal-tier blocks.
	size   [partitionEnd]int
	shares *setShares
}

// NewSlotLimits holds the free slots of each partition and a sorted copy of
// the victim pool.
func NewSlotLimits(freeGeneral, freeReserved uint32, victims []EvictionVictim) *SlotLimits {
	pool := slices.Clone(victims)
	slices.SortFunc(pool, victimOrder)
	return &SlotLimits{freeGeneral: freeGeneral, freeReserved: freeReserved, victims: pool}
}

// Limits is the slot budget of o, the one rule admission and its forecast
// share (spec 5.6): each partition's free slots and size and, once the
// general partition is full and the set is not overfull, the victims pool
// returns, less those of an overfull partition. pool is read only then.
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
	l := NewSlotLimits(slotUnits(s.FreeGeneral), slotUnits(s.FreeReserved), victims)
	l.size[PartitionGeneral], l.size[PartitionReserved] = s.General, s.Reserved
	return l, nil
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
	return &SlotLimits{freeGeneral: s.freeGeneral, freeReserved: s.freeReserved, victims: slices.Clone(s.victims), size: s.size, shares: s.shares.clone()}
}

// Budget bounds a lane by its free slots or, under pressure, its victims:
// those below the highest valid tier, which no work may evict as lower,
// and, once shares are set, the blocks of the lane's partition rotation
// may take. Per-lane readiness and Take decide whether each pick can use
// that room.
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
		lower := v.Tier.Less(highest) && (PartitionOf(lane) == PartitionReserved || v.Partition == PartitionGeneral)
		if lower || (s.shares != nil && v.Rotatable && v.Partition == PartitionOf(lane)) {
			n++
		}
	}
	return min(free+n, MaxCeiling)
}

// Room reports how work d finds room on lane: a free slot of the lane's
// partition (a zero victim) or, under pressure, the first victim in
// eviction order that d strictly outranks, else the equal-tier block
// rotation gives it. Pressure means no free slot for d on any lane it may
// use: general work never takes a reserved slot or evicts a reserved
// entry, reserved work may evict a lower entry in either partition, and
// rotation stays in the lane's partition. ok is false when d must wait.
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
		s.shares.move(v.Partition, d.Scope, v)
		return v, true
	case PartitionOf(lane) == PartitionReserved:
		s.freeReserved -= d.Cost
	default:
		s.freeGeneral -= d.Cost
	}
	// Only one-unit block work writes a record, which then holds the slot.
	if d.Evicts {
		s.shares.move(PartitionOf(lane), d.Scope, EvictionVictim{})
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
	if i := s.rotation(lane, d); i >= 0 {
		return i, true
	}
	return -1, false
}
