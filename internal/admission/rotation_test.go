package admission

import (
	"testing"
	"time"
)

// heldBy is a verified block of scope applied at t0 plus age, whose
// rotation hold has passed when rotatable is set.
func heldBy(t *testing.T, n byte, tier Tier, p Partition, scope string, age time.Duration, rotatable bool) EvictionVictim {
	t.Helper()
	v := victimAt(t, n, tier, p, t0.Add(24*time.Hour))
	v.Scope, v.Applied, v.Rotatable = scope, t0.Add(age), rotatable
	return v
}

// sharedLimits is a full set whose general partition holds size slots,
// shared by the scopes of holding and waiting from cursor.
func sharedLimits(size int, pool []EvictionVictim, holding map[string]int, waiting []string, cursor string) *SlotLimits {
	s := NewSlotLimits(0, 0, pool)
	s.size[PartitionGeneral] = size
	s.Share(map[Partition]map[string]int{PartitionGeneral: holding}, map[Partition][]string{PartitionGeneral: waiting}, QueueCursors{General: cursor})
	return s
}

func fresh(scope string, tier Tier) SlotDemand {
	return SlotDemand{Tier: tier, Cost: 1, Evicts: true, Scope: scope, Fresh: true}
}

// The hold passes only when both wall and elapsed admission time reach
// RotationHold from the verified application, as a charge's window does.
func TestEffectRecordHoldPassed(t *testing.T) {
	applied := EffectRecord{Applied: t0, Elapsed: time.Hour}
	for name, tc := range map[string]struct {
		rec     EffectRecord
		wall    time.Duration
		elapsed time.Duration
		want    bool
	}{
		"exact boundary":           {applied, RotationHold, RotationHold, true},
		"one nanosecond short":     {applied, RotationHold - 1, RotationHold, false},
		"downtime grants nothing":  {applied, 2 * RotationHold, RotationHold - time.Second, false},
		"a slow wall clock waits":  {applied, RotationHold - time.Second, 2 * RotationHold, false},
		"both clocks long past":    {applied, 3 * RotationHold, 3 * RotationHold, true},
		"pending blocks hold":      {EffectRecord{}, 3 * RotationHold, 3 * RotationHold, false},
		"zero elapsed anchor too":  {EffectRecord{Applied: t0}, RotationHold, RotationHold, true},
		"zero elapsed anchor wait": {EffectRecord{Applied: t0}, RotationHold, RotationHold - 1, false},
	} {
		if got := tc.rec.HoldPassed(t0.Add(tc.wall), tc.rec.Elapsed+tc.elapsed); got != tc.want {
			t.Errorf("%s: HoldPassed = %v, want %v", name, got, tc.want)
		}
	}
	if RotationHold != 30*time.Minute {
		t.Fatalf("RotationHold = %v, want the 30-minute minimum of spec 5.6", RotationHold)
	}
}

// The share rule gives the remainder to the scopes after the cursor and
// moves the cursor one scope on.
func TestFairShareRemainderFollowsTheCursor(t *testing.T) {
	keys := []string{"a", "b", "c"}
	for cursor, want := range map[string]map[string]int{
		"":  {"a": 2, "b": 2, "c": 1},
		"a": {"b": 2, "c": 2, "a": 1},
		"c": {"a": 2, "b": 2, "c": 1},
		"b": {"c": 2, "a": 2, "b": 1},
	} {
		f := newFairShare(keys, cursor, 5)
		for k, n := range want {
			if got := f.of(k); got != n {
				t.Errorf("cursor %q: share of %s = %d, want %d", cursor, k, got, n)
			}
		}
	}
	if got := newFairShare(keys, "a", 5).first(); got != "b" {
		t.Fatalf("first after a = %q, want b", got)
	}
	if got := newFairShare(keys, "c", 5).first(); got != "a" {
		t.Fatalf("first after c = %q, want a", got)
	}
	if got := newFairShare(keys, "bb", 6).first(); got != "c" {
		t.Fatalf("first after a missing cursor = %q, want c", got)
	}
}

// Only fresh one-unit block work of tier exactly T rotates an equal-tier
// block of its lane's partition whose hold passed, and only once no free
// slot or strictly lower victim exists.
func TestSlotLimitsRotateOnlyEqualTierWork(t *testing.T) {
	old := heldBy(t, 1, high, PartitionGeneral, "x", 0, true)
	young := heldBy(t, 2, high, PartitionGeneral, "x", time.Hour, false)
	top := heldBy(t, 3, critical, PartitionGeneral, "x", 0, true)
	lower := heldBy(t, 4, warning, PartitionGeneral, "y", 0, false)
	imported := victimAt(t, 5, high, PartitionGeneral, t0.Add(time.Hour))
	imported.Rotatable = true
	reserved := heldBy(t, 6, high, PartitionReserved, "x", 0, true)
	stale := fresh("x", high)
	stale.Fresh = false
	multi := fresh("x", high)
	multi.Cost = 2
	cannot := fresh("x", high)
	cannot.Evicts = false
	own := fresh("x", high)
	own.Target = old.Target
	direct := fresh("x", high)
	direct.Reserved = true
	for name, tc := range map[string]struct {
		pool   []EvictionVictim
		lane   Lane
		demand SlotDemand
		want   EvictionVictim
	}{
		"fresh equal tier rotates":       {[]EvictionVictim{young, old}, LaneGeneral, fresh("x", high), old},
		"strictly lower goes first":      {[]EvictionVictim{old, lower}, LaneGeneral, fresh("x", high), lower},
		"renewed episodes never rotate":  {[]EvictionVictim{old}, LaneGeneral, stale, EvictionVictim{}},
		"held blocks stay":               {[]EvictionVictim{young}, LaneGeneral, fresh("x", high), EvictionVictim{}},
		"higher tiers stay":              {[]EvictionVictim{top}, LaneGeneral, fresh("x", high), EvictionVictim{}},
		"lower work never rotates":       {[]EvictionVictim{old}, LaneGeneral, fresh("x", warning), EvictionVictim{}},
		"imports never rotate":           {[]EvictionVictim{imported}, LaneGeneral, fresh("x", high), EvictionVictim{}},
		"multi-unit work waits":          {[]EvictionVictim{old}, LaneGeneral, multi, EvictionVictim{}},
		"work that cannot evict":         {[]EvictionVictim{old}, LaneGeneral, cannot, EvictionVictim{}},
		"never the own address":          {[]EvictionVictim{old}, LaneGeneral, own, EvictionVictim{}},
		"no cross-partition rotation":    {[]EvictionVictim{old}, LaneDirect, direct, EvictionVictim{}},
		"reserved lanes rotate reserved": {[]EvictionVictim{old, reserved}, LaneDirect, direct, reserved},
		"general turns rotate general":   {[]EvictionVictim{reserved, old}, LaneGeneral, direct, old},
	} {
		s := NewSlotLimits(0, 0, tc.pool)
		s.size[PartitionGeneral], s.size[PartitionReserved] = 4, 1
		s.Share(map[Partition]map[string]int{PartitionGeneral: {"x": 3, "y": 1}, PartitionReserved: {"x": 1}}, nil, QueueCursors{})
		v, ok := s.Room(tc.lane, tc.demand)
		if v != tc.want || ok != (tc.want != EvictionVictim{}) {
			t.Errorf("%s: room = %+v %v, want %+v", name, v, ok, tc.want)
		}
	}
	free := NewSlotLimits(1, 0, []EvictionVictim{old})
	free.size[PartitionGeneral] = 2
	free.Share(map[Partition]map[string]int{PartitionGeneral: {"x": 1}}, map[Partition][]string{PartitionGeneral: {"y"}}, QueueCursors{})
	if v, ok := free.Take(LaneGeneral, fresh("x", high)); !ok || v != (EvictionVictim{}) || len(free.victims) != 1 || free.victims[0] != old {
		t.Fatalf("free capacity rotated or changed a block: %+v %v %+v", v, ok, free.victims)
	}
	otherLane := NewSlotLimits(0, 1, []EvictionVictim{old})
	otherLane.size[PartitionGeneral], otherLane.size[PartitionReserved] = 1, 1
	otherLane.Share(map[Partition]map[string]int{PartitionGeneral: {"x": 1}}, nil, QueueCursors{})
	if v, ok := otherLane.Room(LaneGeneral, direct); ok || v != (EvictionVictim{}) {
		t.Fatalf("rotated while the work has a free reserved slot: %+v %v", v, ok)
	}
	if v, ok := otherLane.Take(LaneDirect, direct); !ok || v != (EvictionVictim{}) || len(otherLane.victims) != 1 {
		t.Fatalf("reserved free slot did not preserve the victim: %+v %v", v, ok)
	}
	if v, ok := NewSlotLimits(0, 0, []EvictionVictim{old}).Room(LaneGeneral, fresh("x", high)); ok {
		t.Fatalf("limits without shares rotated %+v", v)
	}
}

// The victim scope is chosen before age: a requester at or over its share
// rotates only its own blocks; below its share it reclaims only the
// greatest over-share borrowing, never below that scope's share, and
// waits when that scope has no block whose hold passed.
func TestSlotLimitsRotationChoosesTheScopeFirst(t *testing.T) {
	a1 := heldBy(t, 1, high, PartitionGeneral, "a", time.Minute, true)
	a2 := heldBy(t, 2, high, PartitionGeneral, "a", 0, true)
	aYoung := heldBy(t, 3, high, PartitionGeneral, "a", time.Hour, false)
	b1 := heldBy(t, 4, high, PartitionGeneral, "b", 0, true)
	bOlder := heldBy(t, 5, high, PartitionGeneral, "b", -time.Minute, true)
	c1 := heldBy(t, 6, high, PartitionGeneral, "c", 0, true)
	aSame := heldBy(t, 7, high, PartitionGeneral, "a", 0, true)
	if aSame.Action < a2.Action {
		a2, aSame = aSame, a2
	}
	for name, tc := range map[string]struct {
		size    int
		pool    []EvictionVictim
		holding map[string]int
		waiting []string
		cursor  string
		demand  SlotDemand
		want    EvictionVictim
	}{
		"below share reclaims the greatest excess": {6, []EvictionVictim{a1, bOlder}, map[string]int{"a": 4, "b": 2}, nil, "", fresh("c", high), a1},
		"oldest application then action":           {6, []EvictionVictim{a1, aSame, a2}, map[string]int{"a": 6}, nil, "", fresh("c", high), a2},
		"the chosen scope's young blocks wait":     {6, []EvictionVictim{aYoung, b1}, map[string]int{"a": 3, "b": 3}, []string{"c", "d"}, "", fresh("c", high), EvictionVictim{}},
		"at share rotates its own":                 {6, []EvictionVictim{a1, c1}, map[string]int{"a": 3, "c": 3}, nil, "", fresh("c", high), c1},
		"own young blocks wait":                    {6, []EvictionVictim{aYoung, b1}, map[string]int{"a": 4, "b": 2}, nil, "", fresh("a", high), EvictionVictim{}},
		"over share never reclaims others":         {6, []EvictionVictim{b1}, map[string]int{"a": 4, "b": 2}, nil, "", fresh("a", high), EvictionVictim{}},
		"never below another scope's share":        {6, []EvictionVictim{b1}, map[string]int{"a": 4, "b": 2}, nil, "", fresh("c", high), EvictionVictim{}},
		"ties go to the cursor order":              {6, []EvictionVictim{a1, b1}, map[string]int{"a": 3, "b": 3}, nil, "", fresh("c", high), a1},
		"the cursor moves ties":                    {6, []EvictionVictim{a1, b1}, map[string]int{"a": 3, "b": 3}, nil, "a", fresh("c", high), b1},
		"waiting scopes shrink shares":             {6, []EvictionVictim{a1, c1}, map[string]int{"a": 4, "c": 2}, []string{"w"}, "", fresh("c", high), c1},
		"without them the requester reclaims":      {6, []EvictionVictim{a1, c1}, map[string]int{"a": 4, "c": 2}, nil, "", fresh("c", high), a1},
		"the remainder follows the cursor":         {5, []EvictionVictim{a1, b1}, map[string]int{"a": 3, "b": 2}, nil, "", fresh("b", high), b1},
		"the cursor moves the remainder":           {5, []EvictionVictim{a1, b1}, map[string]int{"a": 3, "b": 2}, nil, "a", fresh("b", high), a1},
		"zero share waits despite owning a block":  {1, []EvictionVictim{a1}, map[string]int{"a": 1}, []string{"b"}, "a", fresh("a", high), EvictionVictim{}},
		"positive share may rotate its own block":  {1, []EvictionVictim{a1}, map[string]int{"a": 1}, []string{"b"}, "b", fresh("a", high), a1},
		"at share young own blocks wait":           {6, []EvictionVictim{aYoung, b1}, map[string]int{"a": 3, "b": 3}, nil, "", fresh("a", high), EvictionVictim{}},
		"work names its scope":                     {5, []EvictionVictim{a1}, map[string]int{"a": 4, "b": 1}, nil, "", fresh("", high), EvictionVictim{}},
	} {
		s := sharedLimits(tc.size, tc.pool, tc.holding, tc.waiting, tc.cursor)
		v, ok := s.Room(LaneGeneral, tc.demand)
		if v != tc.want || ok != (tc.want != EvictionVictim{}) {
			t.Errorf("%s: room = %+v %v, want %+v", name, v, ok, tc.want)
		}
	}
}

// Take moves the slot between scopes, so later work in the same cycle
// sees the shares a reservation will see; Room only asks.
func TestSlotLimitsTakeMovesScopeHoldings(t *testing.T) {
	pool := []EvictionVictim{
		heldBy(t, 1, high, PartitionGeneral, "a", 0, true),
		heldBy(t, 2, high, PartitionGeneral, "a", time.Minute, true),
		heldBy(t, 3, high, PartitionGeneral, "a", 2*time.Minute, true),
	}
	s := sharedLimits(4, pool, map[string]int{"a": 4}, nil, "")
	work := fresh("c", high)
	if v, ok := s.Room(LaneGeneral, work); !ok || v != pool[0] {
		t.Fatalf("room = %+v %v", v, ok)
	}
	for i := range 2 {
		if v, ok := s.Take(LaneGeneral, work); !ok || v != pool[i] {
			t.Fatalf("take %d = %+v %v, want %+v", i, v, ok, pool[i])
		}
	}
	if v, ok := s.Take(LaneGeneral, work); ok {
		t.Fatalf("a scope at its share took %+v", v)
	}
	if v, ok := s.Take(LaneGeneral, fresh("a", high)); !ok || v != pool[2] {
		t.Fatalf("the scope that kept its share could not rotate its own: %+v %v", v, ok)
	}
	// The victim's scope gives up its slot: a tie then goes in cursor
	// order, not to the scope that already lost one.
	tie := []EvictionVictim{
		heldBy(t, 4, high, PartitionGeneral, "a", 0, true),
		heldBy(t, 5, high, PartitionGeneral, "a", time.Minute, true),
		heldBy(t, 6, high, PartitionGeneral, "b", 0, true),
	}
	s = sharedLimits(6, tie, map[string]int{"a": 4, "b": 3}, nil, "a")
	for i, want := range []EvictionVictim{tie[0], tie[2]} {
		if v, ok := s.Take(LaneGeneral, work); !ok || v != want {
			t.Fatalf("tie take %d = %+v %v, want %+v", i, v, ok, want)
		}
	}
	// A free slot counts for its scope, so a later scope sees it.
	s = NewSlotLimits(1, 0, pool[:1])
	s.size[PartitionGeneral] = 3
	s.Share(map[Partition]map[string]int{PartitionGeneral: {"a": 2}}, nil, QueueCursors{})
	if v, ok := s.Take(LaneGeneral, work); !ok || v != (EvictionVictim{}) {
		t.Fatalf("free slot take = %+v %v", v, ok)
	}
	if v, ok := s.Take(LaneGeneral, fresh("d", high)); !ok || v != pool[0] {
		t.Fatalf("after a free slot = %+v %v, want the over-share block", v, ok)
	}
	clone := sharedLimits(4, pool, map[string]int{"a": 4}, nil, "")
	copied := clone.Clone()
	if _, ok := copied.Take(LaneGeneral, work); !ok {
		t.Fatal("clone lost its shares")
	}
	if _, ok := copied.Take(LaneGeneral, work); !ok {
		t.Fatal("clone lost its holdings")
	}
	if v, ok := clone.Room(LaneGeneral, work); !ok || v != pool[0] {
		t.Fatalf("a clone's takes moved the original: %+v %v", v, ok)
	}
}

// Free capacity accepts other costs, but only one-unit block work gains
// a scope holding for later rotation decisions.
func TestSlotLimitsFreeSlotsCountOnlyOneUnitBlocks(t *testing.T) {
	for _, lane := range []Lane{LaneGeneral, LaneDirect, LaneCorroborated} {
		t.Run(lane.String(), func(t *testing.T) {
			for name, tc := range map[string]struct {
				cost   uint32
				evicts bool
				want   int
			}{
				"uncharged":      {0, true, 0},
				"multi-unit":     {2, true, 0},
				"non-block":      {1, false, 0},
				"one-unit block": {1, true, 1},
			} {
				t.Run(name, func(t *testing.T) {
					s := NewSlotLimits(2, 2, nil)
					s.Share(nil, nil, QueueCursors{})
					d := fresh("a", high)
					d.Cost, d.Evicts = tc.cost, tc.evicts
					d.Reserved = lane != LaneGeneral
					if v, ok := s.Take(lane, d); !ok || v != (EvictionVictim{}) {
						t.Fatalf("free slot take = %+v, %v", v, ok)
					}
					for _, p := range []Partition{PartitionGeneral, PartitionReserved} {
						wantHolding, wantFree := 0, uint32(2)
						if p == PartitionOf(lane) {
							wantHolding, wantFree = tc.want, 2-tc.cost
						}
						if got := s.shares.holding[p][d.Scope]; got != wantHolding {
							t.Errorf("%s holding = %d, want %d", p, got, wantHolding)
						}
						free := s.freeGeneral
						if p == PartitionReserved {
							free = s.freeReserved
						}
						if free != wantFree {
							t.Errorf("%s free slots = %d, want %d", p, free, wantFree)
						}
					}
				})
			}
		})
	}
}

// A lane's budget counts the blocks rotation may take once shares are
// known, including the highest tier, in the lane's own partition only.
func TestSlotLimitsBudgetCountsRotatableBlocks(t *testing.T) {
	pool := []EvictionVictim{
		heldBy(t, 1, critical, PartitionGeneral, "a", 0, true),
		heldBy(t, 2, critical, PartitionReserved, "a", 0, true),
		heldBy(t, 3, critical, PartitionGeneral, "a", time.Hour, false),
	}
	s := NewSlotLimits(0, 0, pool)
	if s.Budget(LaneGeneral) != 0 || s.Budget(LaneDirect) != 0 {
		t.Fatalf("budgets without shares %d %d, want 0", s.Budget(LaneGeneral), s.Budget(LaneDirect))
	}
	s.Share(map[Partition]map[string]int{PartitionGeneral: {"a": 2}, PartitionReserved: {"a": 1}}, nil, QueueCursors{})
	if s.Budget(LaneGeneral) != 1 || s.Budget(LaneDirect) != 1 || s.Budget(LaneCorroborated) != 1 {
		t.Fatalf("budgets with shares %d %d %d, want 1 each", s.Budget(LaneGeneral), s.Budget(LaneDirect), s.Budget(LaneCorroborated))
	}
}

// Advance moves each partition's cursor to the first active scope after
// it; a partition with no active scope keeps its cursor.
func TestSlotLimitsAdvanceMovesTheCursors(t *testing.T) {
	s := NewSlotLimits(0, 0, nil)
	s.Share(map[Partition]map[string]int{PartitionGeneral: {"a": 1, "c": 0}}, map[Partition][]string{PartitionGeneral: {"b"}}, QueueCursors{General: "a", Reserved: "z"})
	if got := s.Advance(); got != (QueueCursors{General: "b", Reserved: "z"}) {
		t.Fatalf("advance = %+v", got)
	}
	if got := s.Advance(); got != (QueueCursors{General: "a", Reserved: "z"}) {
		t.Fatalf("second advance = %+v", got)
	}
	var none *SlotLimits
	if got := none.Advance(); got != (QueueCursors{}) {
		t.Fatalf("nil limits advanced %+v", got)
	}
	if got := NewSlotLimits(0, 0, nil).Advance(); got != (QueueCursors{}) {
		t.Fatalf("limits without shares advanced %+v", got)
	}
}

// The set budget sizes its partitions for the shares.
func TestSetOccupancyLimitsSizeThePartitions(t *testing.T) {
	victim := heldBy(t, 1, high, PartitionGeneral, "a", 0, true)
	s, err := SetOccupancy{Limit: 10, General: 8, Reserved: 2}.Limits(func() ([]EvictionVictim, error) { return []EvictionVictim{victim}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if s.size[PartitionGeneral] != 8 || s.size[PartitionReserved] != 2 {
		t.Fatalf("sizes %v", s.size)
	}
	s.Share(map[Partition]map[string]int{PartitionGeneral: {"a": 8}}, nil, QueueCursors{})
	if v, ok := s.Room(LaneGeneral, fresh("b", high)); !ok || v != victim {
		t.Fatalf("room = %+v %v", v, ok)
	}
}

// An import carries no rotation fields: the engine's list cannot make one
// rotatable.
func TestEvictionVictimImportedHasNoRotationFields(t *testing.T) {
	base := EvictionVictim{Action: importName(1), Target: mustAddr(t, "192.0.2.1"), Tier: ImportTier, Partition: PartitionGeneral, ExpiresAt: t0}
	if !base.Imported() {
		t.Fatal("a plain import is not imported")
	}
	for name, mutate := range map[string]func(*EvictionVictim){
		"scope":     func(v *EvictionVictim) { v.Scope = "a" },
		"applied":   func(v *EvictionVictim) { v.Applied = t0 },
		"rotatable": func(v *EvictionVictim) { v.Rotatable = true },
	} {
		v := base
		mutate(&v)
		if v.Imported() {
			t.Errorf("an import with a %s is imported", name)
		}
	}
}
