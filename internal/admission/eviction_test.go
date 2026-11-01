package admission

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

func victimAt(t *testing.T, n byte, tier Tier, p Partition, expires time.Time) EvictionVictim {
	t.Helper()
	return EvictionVictim{Action: testActionID(t, n), Target: mustAddr(t, fmt.Sprintf("198.51.100.%d", n)), Tier: tier, Partition: p, ExpiresAt: expires}
}

var (
	warning  = Tier{Class: ClassC1, Severity: SeverityWarning}
	high     = Tier{Class: ClassC2, Severity: SeverityHigh}
	critical = Tier{Class: ClassC3, Severity: SeverityCritical}
)

// A full partition yields to strictly higher work: the lowest tier goes
// first, then the earliest expiry, then the lowest action ID (spec 5.6).
func TestSlotLimitsChooseTheLowestVictim(t *testing.T) {
	soon, late := t0.Add(time.Hour), t0.Add(2*time.Hour)
	victims := []EvictionVictim{
		victimAt(t, 1, high, PartitionGeneral, soon),
		victimAt(t, 2, warning, PartitionGeneral, late),
		victimAt(t, 3, warning, PartitionGeneral, soon),
		victimAt(t, 4, warning, PartitionGeneral, soon),
	}
	if victims[3].Action < victims[2].Action {
		victims[2], victims[3] = victims[3], victims[2]
	}
	want := []ActionID{victims[2].Action, victims[3].Action, victims[1].Action, victims[0].Action}
	s := NewSlotLimits(0, 0, victims)
	work := SlotDemand{Tier: critical, Cost: 1, Evicts: true}
	for i, action := range want {
		v, ok := s.Take(LaneGeneral, work)
		if !ok || v.Action != action {
			t.Fatalf("victim %d = %+v %v, want %s", i, v, ok, action)
		}
	}
	if _, ok := s.Take(LaneGeneral, work); ok {
		t.Fatal("an emptied pool still funded work")
	}
}

// Only strictly lower work is a victim, only one-unit work that may evict
// takes one, and a free slot is taken before anyone is evicted.
func TestSlotLimitsEvictOnlyUnderPressure(t *testing.T) {
	pool := []EvictionVictim{victimAt(t, 1, high, PartitionGeneral, t0.Add(time.Hour))}
	for name, tc := range map[string]struct {
		free   uint32
		demand SlotDemand
		ok     bool
		evicts bool
	}{
		"free slot first":        {1, SlotDemand{Tier: critical, Cost: 1, Evicts: true}, true, false},
		"strictly higher":        {0, SlotDemand{Tier: critical, Cost: 1, Evicts: true}, true, true},
		"equal tier waits":       {0, SlotDemand{Tier: high, Cost: 1, Evicts: true}, false, false},
		"lower tier waits":       {0, SlotDemand{Tier: warning, Cost: 1, Evicts: true}, false, false},
		"work that cannot evict": {0, SlotDemand{Tier: critical, Cost: 1}, false, false},
		"multi-unit work waits":  {0, SlotDemand{Tier: critical, Cost: 2, Evicts: true}, false, false},
		"multi-unit free slots":  {2, SlotDemand{Tier: critical, Cost: 2, Evicts: true}, true, false},
		"uncharged work":         {0, SlotDemand{Tier: warning}, true, false},
	} {
		s := NewSlotLimits(tc.free, 0, pool)
		v, ok := s.Room(LaneGeneral, tc.demand)
		if ok != tc.ok || (v != EvictionVictim{}) != tc.evicts {
			t.Errorf("%s: room %+v %v, want ok %v evicting %v", name, v, ok, tc.ok, tc.evicts)
		}
		if again, againOK := s.Room(LaneGeneral, tc.demand); again != v || againOK != ok {
			t.Errorf("%s: Room consumed the set", name)
		}
	}
}

// General work never takes a reserved slot or evicts a reserved entry;
// reserved work evicts in either partition but never while a free slot
// waits for one of its turns.
func TestSlotLimitsKeepThePartitions(t *testing.T) {
	general := victimAt(t, 1, warning, PartitionGeneral, t0.Add(2*time.Hour))
	reserved := victimAt(t, 2, warning, PartitionReserved, t0.Add(time.Hour))
	pool := []EvictionVictim{general, reserved}
	critical := SlotDemand{Tier: critical, Cost: 1, Evicts: true}
	eligible := critical
	eligible.Reserved = true
	for name, tc := range map[string]struct {
		freeGeneral, freeReserved uint32
		lane                      Lane
		demand                    SlotDemand
		want                      EvictionVictim
		ok                        bool
	}{
		"general work keeps to its partition":    {0, 0, LaneGeneral, critical, general, true},
		"general work never takes reserved room": {0, 1, LaneGeneral, critical, general, true},
		"reserved work evicts across partitions": {0, 0, LaneDirect, eligible, reserved, true},
		"reserved work waits for a general slot": {1, 0, LaneDirect, eligible, EvictionVictim{}, false},
		"general turn waits for a reserved slot": {0, 1, LaneGeneral, eligible, EvictionVictim{}, false},
		"reserved slot first":                    {0, 1, LaneCorroborated, eligible, EvictionVictim{}, true},
	} {
		s := NewSlotLimits(tc.freeGeneral, tc.freeReserved, pool)
		v, ok := s.Take(tc.lane, tc.demand)
		if v != tc.want || ok != tc.ok {
			t.Errorf("%s: %+v %v, want %+v %v", name, v, ok, tc.want, tc.ok)
		}
	}
}

// The lane budget exposes free slots first and victims under pressure.
// Clones consume their own free slots and victims.
func TestSlotLimitsBudget(t *testing.T) {
	pool := []EvictionVictim{
		victimAt(t, 1, warning, PartitionGeneral, t0.Add(time.Hour)),
		victimAt(t, 2, warning, PartitionReserved, t0.Add(time.Hour)),
	}
	s := NewSlotLimits(3, 1, pool)
	if s.Budget(LaneGeneral) != 3 || s.Budget(LaneDirect) != 1 {
		t.Fatalf("budgets %d %d, want 3 and 1", s.Budget(LaneGeneral), s.Budget(LaneDirect))
	}
	c := s.Clone()
	if _, ok := c.Take(LaneGeneral, SlotDemand{Tier: critical, Cost: 3, Evicts: true}); !ok || c.Budget(LaneGeneral) != 1 || s.Budget(LaneGeneral) != 3 {
		t.Fatalf("budget after taking three free slots %d, original %d", c.Budget(LaneGeneral), s.Budget(LaneGeneral))
	}
	if v, ok := c.Take(LaneGeneral, SlotDemand{Tier: critical, Cost: 1, Evicts: true}); !ok || v.Partition != PartitionGeneral || c.Budget(LaneGeneral) != 0 {
		t.Fatalf("eviction %+v %v left budget %d", v, ok, c.Budget(LaneGeneral))
	}
	full := NewSlotLimits(0, 0, pool)
	if full.Budget(LaneGeneral) != 1 || full.Budget(LaneDirect) != 2 {
		t.Fatalf("full budgets %d %d", full.Budget(LaneGeneral), full.Budget(LaneDirect))
	}
	var unbounded *SlotLimits
	if unbounded.Budget(LaneGeneral) != MaxCeiling || unbounded.Clone() != nil {
		t.Fatal("nil limits bound nothing")
	}
	if v, ok := unbounded.Room(LaneGeneral, SlotDemand{Tier: warning, Cost: 2}); !ok || v != (EvictionVictim{}) {
		t.Fatal("nil limits always have room")
	}
}

// The limits sort their own copy of the pool, so a caller's later change
// cannot alter a choice.
func TestNewSlotLimitsOwnsItsPool(t *testing.T) {
	pool := []EvictionVictim{
		victimAt(t, 1, high, PartitionGeneral, t0.Add(time.Hour)),
		victimAt(t, 2, warning, PartitionGeneral, t0.Add(time.Hour)),
	}
	original := slices.Clone(pool)
	s := NewSlotLimits(0, 0, pool)
	if !slices.Equal(pool, original) {
		t.Fatal("constructing limits reordered the caller's pool")
	}
	for i := range pool {
		pool[i].Tier = critical
	}
	if v, ok := s.Take(LaneGeneral, SlotDemand{Tier: high, Cost: 1, Evicts: true}); !ok || v.Action != testActionID(t, 2) || v.Tier != warning {
		t.Fatalf("pool aliased its caller: %+v %v", v, ok)
	}
}

// The highest valid tier cannot be evicted by any work, so it cannot
// fund a lane's budget even when every partition is full.
func TestSlotLimitsBudgetExcludesHighestTier(t *testing.T) {
	belowCritical := Tier{Class: ClassC3, Severity: SeverityHigh}
	pool := []EvictionVictim{
		victimAt(t, 1, critical, PartitionGeneral, t0.Add(time.Hour)),
		victimAt(t, 2, critical, PartitionReserved, t0.Add(time.Hour)),
		victimAt(t, 3, belowCritical, PartitionGeneral, t0.Add(time.Hour)),
		victimAt(t, 4, belowCritical, PartitionReserved, t0.Add(time.Hour)),
	}
	for _, lane := range []Lane{LaneGeneral, LaneDirect, LaneCorroborated} {
		t.Run(lane.String(), func(t *testing.T) {
			s := NewSlotLimits(0, 0, pool)
			demand := SlotDemand{Tier: critical, Cost: 1, Evicts: true, Reserved: lane != LaneGeneral}
			want := uint32(1)
			if lane != LaneGeneral {
				want = 2
			}
			for want > 0 {
				if got := s.Budget(lane); got != want {
					t.Errorf("budget = %d, want %d evictable entries", got, want)
				}
				v, ok := s.Take(lane, demand)
				if !ok || v.Tier != belowCritical {
					t.Fatalf("take = %+v, %v; want a lower-tier victim", v, ok)
				}
				want--
			}
			if got := s.Budget(lane); got != 0 {
				t.Errorf("exhausted budget = %d, want 0", got)
			}
			if v, ok := s.Take(lane, demand); ok || v != (EvictionVictim{}) {
				t.Fatalf("exhausted take = %+v, %v", v, ok)
			}
		})
	}
}

func TestSlotLimitsCloneOwnsVictims(t *testing.T) {
	pool := []EvictionVictim{
		victimAt(t, 1, warning, PartitionGeneral, t0.Add(time.Hour)),
		victimAt(t, 2, high, PartitionGeneral, t0.Add(time.Hour)),
		victimAt(t, 3, high, PartitionReserved, t0.Add(2*time.Hour)),
	}
	original := NewSlotLimits(0, 0, pool)
	clone := original.Clone()
	demand := SlotDemand{Tier: critical, Cost: 1, Evicts: true, Reserved: true}
	for _, want := range pool {
		for _, limits := range []*SlotLimits{clone, original} {
			v, ok := limits.Take(LaneDirect, demand)
			if !ok || v != want {
				t.Fatalf("take = %+v, %v; want %+v from each copy", v, ok, want)
			}
		}
	}
	for _, limits := range []*SlotLimits{clone, original} {
		if _, ok := limits.Take(LaneDirect, demand); ok {
			t.Fatal("a consumed victim was granted again")
		}
	}
}

func TestSlotLimitsTakeConsumesOnlyGrantedSlots(t *testing.T) {
	for _, lane := range []Lane{LaneGeneral, LaneDirect, LaneCorroborated} {
		t.Run(lane.String(), func(t *testing.T) {
			s := NewSlotLimits(2, 2, nil)
			demand := SlotDemand{Tier: critical, Cost: 3, Evicts: true, Reserved: lane != LaneGeneral}
			check := func(cost uint32, wantOK bool) {
				t.Helper()
				demand.Cost = cost
				beforeGeneral, beforeReserved := s.freeGeneral, s.freeReserved
				room, roomOK := s.Room(lane, demand)
				if s.freeGeneral != beforeGeneral || s.freeReserved != beforeReserved {
					t.Fatal("Room consumed free slots")
				}
				v, ok := s.Take(lane, demand)
				if ok != wantOK || roomOK != wantOK || v != (EvictionVictim{}) || room != v {
					t.Fatalf("cost %d: Room = %+v, %v; Take = %+v, %v; want %v", cost, room, roomOK, v, ok, wantOK)
				}
				wantGeneral, wantReserved := beforeGeneral, beforeReserved
				if wantOK {
					if lane == LaneGeneral {
						wantGeneral -= cost
					} else {
						wantReserved -= cost
					}
				}
				if s.freeGeneral != wantGeneral || s.freeReserved != wantReserved {
					t.Fatalf("slots = (%d, %d), want (%d, %d)", s.freeGeneral, s.freeReserved, wantGeneral, wantReserved)
				}
			}
			check(^uint32(0), false)
			check(3, false)
			check(0, true)
			check(1, true)
			check(2, false)
			check(1, true)
			check(1, false)
			check(0, true)
		})
	}
}

// Work never evicts the block of its own address: an intent and the
// ledger's open proof both refuse that removal.
func TestSlotLimitsNeverEvictTheSameAddress(t *testing.T) {
	own := victimAt(t, 1, warning, PartitionGeneral, t0.Add(time.Hour))
	other := victimAt(t, 2, warning, PartitionGeneral, t0.Add(2*time.Hour))
	work := SlotDemand{Tier: critical, Cost: 1, Evicts: true, Target: own.Target}
	if v, ok := NewSlotLimits(0, 0, []EvictionVictim{own, other}).Room(LaneGeneral, work); !ok || v.Action != other.Action {
		t.Fatalf("room = %+v %v, want the other address", v, ok)
	}
	if v, ok := NewSlotLimits(0, 0, []EvictionVictim{own}).Take(LaneGeneral, work); ok {
		t.Fatalf("took the own address %+v", v)
	}
}
