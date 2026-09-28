package admission

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"
)

func schedItem(id, scope string, class Class, sev Severity, age time.Duration) ScheduleItem {
	return ScheduleItem{ID: CandidateID(id), Scope: scope, Tier: Tier{class, sev}, Queued: t0.Add(-age), Cost: 1, Ready: true}
}

func picked(picks []Pick) []string {
	out := make([]string, len(picks))
	for i, p := range picks {
		out[i] = string(p.ID)
	}
	return out
}

func mustSchedule(t *testing.T, items []ScheduleItem, st ScheduleState, lim ScheduleLimits) ([]Pick, ScheduleState) {
	t.Helper()
	picks, next, err := Schedule(items, st, lim)
	if err != nil {
		t.Fatal(err)
	}
	return picks, next
}

var wide = ScheduleLimits{General: 1000, Reserved: 1000, Members: MaxBatchMembers}

// The general lane serves classes C3:C2:C1 4:2:1 and lends an empty class's
// turns to the next class with work.
func TestScheduleClassQuanta(t *testing.T) {
	var items []ScheduleItem
	for i := 0; i < 20; i++ {
		for _, c := range []Class{ClassC1, ClassC2, ClassC3} {
			items = append(items, schedItem(fmt.Sprintf("%s-%02d", c, i), "s", c, SeverityHigh, time.Duration(20-i)*time.Minute))
		}
	}
	picks, st := mustSchedule(t, items, ScheduleState{}, ScheduleLimits{General: 7, Members: 7})
	var classes []Class
	for _, p := range picks {
		for _, it := range items {
			if it.ID == p.ID {
				classes = append(classes, it.Tier.Class)
			}
		}
	}
	if want := []Class{ClassC3, ClassC3, ClassC3, ClassC3, ClassC2, ClassC2, ClassC1}; !reflect.DeepEqual(classes, want) {
		t.Fatalf("classes = %v, want %v", classes, want)
	}
	if st.ClassSlot != 0 {
		t.Fatalf("class slot after one round = %d", st.ClassSlot)
	}
	var noC3 []ScheduleItem
	for _, it := range items {
		if it.Tier.Class != ClassC3 {
			noC3 = append(noC3, it)
		}
	}
	picks, _ = mustSchedule(t, noC3, ScheduleState{}, ScheduleLimits{General: 6, Members: 6})
	if got := picked(picks); !reflect.DeepEqual(got, []string{"c2-00", "c2-01", "c1-00", "c2-02", "c2-03", "c1-01"}) {
		t.Fatalf("without C3 = %v", got)
	}
}

// Verified scopes rotate: a scope with many candidates cannot take another
// scope's turn.
func TestScheduleRotatesScopes(t *testing.T) {
	var items []ScheduleItem
	for i := 0; i < 10; i++ {
		items = append(items, schedItem(fmt.Sprintf("flood-%02d", i), "acct:a#1/address", ClassC2, SeverityCritical, time.Hour))
	}
	items = append(items, schedItem("lone", "host/address", ClassC2, SeverityWarning, 0))
	picks, st := mustSchedule(t, items, ScheduleState{}, ScheduleLimits{General: 2, Members: 2})
	if got := picked(picks); !reflect.DeepEqual(got, []string{"flood-00", "lone"}) {
		t.Fatalf("first turns = %v", got)
	}
	picks, _ = mustSchedule(t, items[1:10], st, ScheduleLimits{General: 1, Members: 1})
	if got := picked(picks); !reflect.DeepEqual(got, []string{"flood-01"}) {
		t.Fatalf("after the lone scope emptied = %v", got)
	}
}

// Inside a scope, severities take turns Critical:High:Warning 4:2:1, and a
// severity serves its oldest candidate first, then the lowest ID.
func TestScheduleSeverityQuantaAndAge(t *testing.T) {
	var items []ScheduleItem
	for i := 0; i < 8; i++ {
		for _, sev := range []Severity{SeverityWarning, SeverityHigh, SeverityCritical} {
			items = append(items, schedItem(fmt.Sprintf("%s-%d", sev, i), "s", ClassC2, sev, time.Duration(8-i)*time.Minute))
		}
	}
	tie := schedItem("critical-0a", "s", ClassC2, SeverityCritical, 8*time.Minute)
	items = append(items, tie)
	picks, _ := mustSchedule(t, items, ScheduleState{}, ScheduleLimits{General: 7, Members: 7})
	want := []string{"critical-0", "critical-0a", "critical-1", "critical-2", "high-0", "high-1", "warning-0"}
	if got := picked(picks); !reflect.DeepEqual(got, want) {
		t.Fatalf("severity order = %v, want %v", got, want)
	}
}

// The reserved lane alternates direct and corroborated turns while both have
// work; a reserved pick is never also a general one, and a direct candidate
// can still take its general C3 turn.
func TestScheduleReservedLane(t *testing.T) {
	direct := func(id string) ScheduleItem {
		it := schedItem(id, "s", ClassC3, SeverityHigh, time.Hour)
		it.Direct = true
		return it
	}
	corroborated := func(id string) ScheduleItem {
		it := schedItem(id, "s", ClassC3, SeverityHigh, time.Hour)
		it.Corroborated = true
		return it
	}
	items := []ScheduleItem{direct("d1"), direct("d2"), direct("d3"), corroborated("k1"), corroborated("k2")}
	picks, st := mustSchedule(t, items, ScheduleState{}, ScheduleLimits{Reserved: 4, Members: 4})
	if got := picked(picks); !reflect.DeepEqual(got, []string{"d1", "k1", "d2", "k2"}) {
		t.Fatalf("reserved turns = %v", got)
	}
	for i, lane := range []Lane{LaneDirect, LaneCorroborated, LaneDirect, LaneCorroborated} {
		if picks[i].Lane != lane {
			t.Fatalf("pick %d lane = %s", i, picks[i].Lane)
		}
	}
	if st.NextCorroborated {
		t.Fatal("after a corroborated turn the direct turn is next")
	}
	picks, _ = mustSchedule(t, items, ScheduleState{}, ScheduleLimits{Reserved: 1, General: 1, Members: 2})
	if got := picked(picks); !reflect.DeepEqual(got, []string{"d1", "d2"}) || picks[1].Lane != LaneGeneral {
		t.Fatalf("reserved then general = %v", picks)
	}
	general := schedItem("g", "s", ClassC3, SeverityCritical, 2*time.Hour)
	picks, _ = mustSchedule(t, []ScheduleItem{general}, ScheduleState{}, ScheduleLimits{Reserved: 5, Members: 5})
	if len(picks) != 0 {
		t.Fatalf("reserved budget served a general candidate: %v", picks)
	}
}

// Deficit accounting in block units: a scope whose next candidate costs more
// than one turn earns a unit per turn and is served once it has earned the
// cost, while cheaper scopes keep their turns. A head costing more than the
// remaining budget is passed over without spending its scope's deficit.
func TestScheduleDeficitAccounting(t *testing.T) {
	big := schedItem("big", "a", ClassC2, SeverityHigh, time.Hour)
	big.Cost = 3
	var items = []ScheduleItem{big}
	for i := 0; i < 6; i++ {
		items = append(items, schedItem(fmt.Sprintf("small-%d", i), "b", ClassC2, SeverityHigh, time.Duration(6-i)*time.Minute))
	}
	picks, st := mustSchedule(t, items, ScheduleState{}, ScheduleLimits{General: 100, Members: 4})
	if got := picked(picks); !reflect.DeepEqual(got, []string{"small-0", "small-1", "big", "small-2"}) {
		t.Fatalf("deficit order = %v", got)
	}
	if st.Rings[ringC2].Scopes["a"] != (ScopeTurn{}) {
		t.Fatalf("served big candidate left a deficit: %+v", st.Rings[ringC2].Scopes["a"])
	}
	picks, st = mustSchedule(t, items, ScheduleState{}, ScheduleLimits{General: 2, Members: 4})
	if got := picked(picks); !reflect.DeepEqual(got, []string{"small-0", "small-1"}) {
		t.Fatalf("budget-limited order = %v", got)
	}
	if turn := st.Rings[ringC2].Scopes["a"]; turn.Deficit != 2 {
		t.Fatalf("deficit of the waiting big candidate = %+v, want the two units it earned", turn)
	}
	picks, _ = mustSchedule(t, items, st, ScheduleLimits{General: 1, Members: 1})
	if got := picked(picks); !reflect.DeepEqual(got, []string{"small-0"}) {
		t.Fatalf("a head over the budget took the turn: %v", got)
	}
	st.Rings[ringC2].Scopes["a"] = ScopeTurn{Deficit: MaxMemberCost}
	_, st = mustSchedule(t, items, st, ScheduleLimits{General: 2, Members: 2})
	if turn := st.Rings[ringC2].Scopes["a"]; turn.Deficit != MaxMemberCost {
		t.Fatalf("deficit grew past the bound: %+v", turn)
	}
}

// A member that fits a fresh budget must eventually get it. Cheaper work
// in earlier classes or another scope cannot consume its budget every time.
func TestSchedulePreservesBudgetBlockedTurns(t *testing.T) {
	for _, cost := range []uint32{2, MaxMemberCost} {
		for _, class := range []Class{ClassC2, ClassC1} {
			t.Run(fmt.Sprintf("%s/cost=%d", class, cost), func(t *testing.T) {
				large := schedItem("large", "a", class, SeverityHigh, time.Hour)
				large.Cost = cost
				items := []ScheduleItem{large}
				for i := 0; i < 4*(int(cost)+2); i++ {
					for _, c := range []Class{ClassC3, ClassC2, ClassC1} {
						if class == ClassC2 && c == class {
							continue
						}
						it := schedItem(fmt.Sprintf("%s-%03d", c, i), "b", c, SeverityHigh, 0)
						if c == ClassC3 {
							it.Cost = cost / 2
						}
						items = append(items, it)
					}
				}
				// Four C3 turns leave one unit for C2, or three units
				// for two C2 turns and a cheaper peer in C1.
				budget := 2*cost + 1
				if class == ClassC1 {
					budget += 2
				}
				assertScheduleProgress(t, items, ScheduleState{}, ScheduleLimits{General: budget, Members: MaxBatchMembers}, large)
			})
		}
	}
}

func TestSchedulePreservesReservedBudgetBlockedTurns(t *testing.T) {
	for _, cost := range []uint32{2, MaxMemberCost} {
		for _, direct := range []bool{false, true} {
			t.Run(fmt.Sprintf("direct=%t/cost=%d", direct, cost), func(t *testing.T) {
				large := schedItem("large", "a", ClassC3, SeverityHigh, time.Hour)
				large.Cost, large.Direct, large.Corroborated = cost, direct, !direct
				items := []ScheduleItem{large}
				for i := 0; i < int(cost)+2; i++ {
					for _, d := range []bool{false, true} {
						it := schedItem(fmt.Sprintf("%t-%03d", d, i), "b", ClassC3, SeverityHigh, 0)
						it.Direct, it.Corroborated = d, !d
						if d != direct {
							it.Cost = cost - 1
						}
						items = append(items, it)
					}
				}
				st := ScheduleState{NextCorroborated: direct}
				assertScheduleProgress(t, items, st, ScheduleLimits{Reserved: cost, Members: MaxBatchMembers}, large)
			})
		}
	}
}

// An empty class or sub-lane may gain work before the next call. That new
// work must not take the fresh budget promised to a blocked turn.
func TestScheduleBudgetBlockedTurnPrecedesNewWork(t *testing.T) {
	for _, reserved := range []bool{false, true} {
		t.Run(fmt.Sprintf("reserved=%t", reserved), func(t *testing.T) {
			first := schedItem("first", "a", ClassC3, SeverityHigh, time.Hour)
			large := schedItem("large", "b", ClassC2, SeverityHigh, time.Hour)
			arrival := schedItem("arrival", "a", ClassC3, SeverityHigh, 0)
			large.Cost = 2
			lim := ScheduleLimits{General: 2, Members: MaxBatchMembers}
			if reserved {
				lim.General, lim.Reserved = 0, 2
				large.Tier.Class = ClassC3
				first.Direct, large.Direct, arrival.Corroborated = true, true, true
			}
			picks, st := mustSchedule(t, []ScheduleItem{first, large}, ScheduleState{}, lim)
			if got := picked(picks); !reflect.DeepEqual(got, []string{"first"}) {
				t.Fatalf("first batch = %v", got)
			}
			picks, _ = mustSchedule(t, []ScheduleItem{arrival, large}, st, lim)
			if got := picked(picks); !reflect.DeepEqual(got, []string{"large"}) {
				t.Fatalf("new work took the blocked turn's budget: %v", got)
			}
		})
	}
}

// A spent reserved budget ends the batch where it stands: an empty
// sub-lane keeps the next turn although the other one still has work.
func TestScheduleSpentReservedBudgetKeepsTurn(t *testing.T) {
	lim := ScheduleLimits{Reserved: 1, Members: MaxBatchMembers}
	c1 := schedItem("c1", "a", ClassC3, SeverityHigh, time.Hour)
	c2 := schedItem("c2", "a", ClassC3, SeverityHigh, 0)
	c1.Corroborated, c2.Corroborated = true, true
	picks, st := mustSchedule(t, []ScheduleItem{c1, c2}, ScheduleState{}, lim)
	if got := picked(picks); !reflect.DeepEqual(got, []string{"c1"}) {
		t.Fatalf("first batch = %v", got)
	}
	d1 := schedItem("d1", "b", ClassC3, SeverityHigh, 0)
	d1.Direct = true
	picks, _ = mustSchedule(t, []ScheduleItem{c2, d1}, st, lim)
	if got := picked(picks); !reflect.DeepEqual(got, []string{"d1"}) {
		t.Fatalf("the sub-lane just served took the next turn: %v", got)
	}
}

func assertScheduleProgress(t *testing.T, items []ScheduleItem, st ScheduleState, lim ScheduleLimits, target ScheduleItem) {
	t.Helper()
	for round := 0; round < int(target.Cost)+2; round++ {
		picks, next := mustSchedule(t, items, st, lim)
		served := map[CandidateID]bool{}
		for _, p := range picks {
			if p.ID == target.ID {
				return
			}
			served[p.ID] = true
		}
		kept := items[:0]
		for _, it := range items {
			if !served[it.ID] {
				kept = append(kept, it)
			}
		}
		items = kept
		// Every call uses a decoded checkpoint, as after a ledger reopen.
		data, err := next.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		st, err = UnmarshalScheduleState(data)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("cheaper work starved a member that fits the full budget")
}

// A candidate waiting to retry is never picked, and does not cost its scope
// the deficit it has earned. A scope with no work left loses its turn state.
func TestScheduleSkipsWaitingCandidates(t *testing.T) {
	waiting := schedItem("waiting", "a", ClassC2, SeverityHigh, time.Hour)
	waiting.Ready, waiting.Cost = false, 5
	st := ScheduleState{}
	st.Rings[ringC2] = Ring{Scopes: map[string]ScopeTurn{"a": {Deficit: 3}, "gone": {Deficit: 1}}}
	items := []ScheduleItem{waiting, schedItem("ready", "b", ClassC2, SeverityHigh, 0)}
	picks, next := mustSchedule(t, items, st, wide)
	if got := picked(picks); !reflect.DeepEqual(got, []string{"ready"}) {
		t.Fatalf("picks = %v", got)
	}
	if turn := next.Rings[ringC2].Scopes["a"]; turn.Deficit != 3 {
		t.Fatalf("waiting scope deficit = %+v", turn)
	}
	if _, kept := next.Rings[ringC2].Scopes["gone"]; kept {
		t.Fatal("a scope without work kept its turn")
	}
	if len(st.Rings[ringC2].Scopes) != 2 {
		t.Fatal("Schedule changed its input state")
	}
}

func TestScheduleRefusesInvalidInput(t *testing.T) {
	good := schedItem("x", "s", ClassC2, SeverityHigh, 0)
	for name, tc := range map[string]struct {
		items []ScheduleItem
		st    ScheduleState
		lim   ScheduleLimits
	}{
		"no members":          {[]ScheduleItem{good}, ScheduleState{}, ScheduleLimits{Members: 0}},
		"too many members":    {[]ScheduleItem{good}, ScheduleState{}, ScheduleLimits{Members: MaxBatchMembers + 1}},
		"repeated item":       {[]ScheduleItem{good, good}, ScheduleState{}, wide},
		"no scope":            {[]ScheduleItem{{ID: "y", Tier: good.Tier, Cost: 1}}, ScheduleState{}, wide},
		"zero cost":           {[]ScheduleItem{{ID: "y", Scope: "s", Tier: good.Tier}}, ScheduleState{}, wide},
		"cost over the bound": {[]ScheduleItem{{ID: "y", Scope: "s", Tier: good.Tier, Cost: MaxMemberCost + 1}}, ScheduleState{}, wide},
		"both reserved turns": {[]ScheduleItem{{ID: "y", Scope: "s", Tier: Tier{ClassC3, SeverityHigh}, Cost: 1, Direct: true, Corroborated: true}}, ScheduleState{}, wide},
		"reserved below C3":   {[]ScheduleItem{{ID: "y", Scope: "s", Tier: good.Tier, Cost: 1, Direct: true}}, ScheduleState{}, wide},
		"class slot":          {[]ScheduleItem{good}, ScheduleState{ClassSlot: 7}, wide},
	} {
		if _, _, err := Schedule(tc.items, tc.st, tc.lim); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestScheduleStateRoundTrips(t *testing.T) {
	st := ScheduleState{ClassSlot: 5, NextCorroborated: true}
	st.Rings[ringC3] = Ring{Last: "host/address", Scopes: map[string]ScopeTurn{"acct:a#1/address": {Severity: 4, Deficit: 2}, "host/address": {Deficit: 64}}}
	data, err := st.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalScheduleState(data)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := back.MarshalBinary(); !bytes.Equal(again, data) || back.Rings[ringC3].Scopes["host/address"].Deficit != 64 {
		t.Fatalf("round trip = %+v", back)
	}
	for name, bad := range map[string]ScheduleState{
		"deficit":  {Rings: [ringCount]Ring{{Scopes: map[string]ScopeTurn{"s": {Deficit: MaxMemberCost + 1}}}}},
		"severity": {Rings: [ringCount]Ring{{Scopes: map[string]ScopeTurn{"s": {Severity: 7}}}}},
		"default":  {Rings: [ringCount]Ring{{Scopes: map[string]ScopeTurn{"s": {}}}}},
		"cursor":   {Rings: [ringCount]Ring{{Last: "a b"}}},
	} {
		if _, err := bad.MarshalBinary(); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"flipped byte":   func() []byte { d := bytes.Clone(data); d[3] ^= 1; return d }(),
		"missing ring":   resealForTest(bytes.Replace(body, []byte(`{"scopes":[]},`), nil, 1)),
		"unsorted":       resealForTest(bytes.Replace(body, []byte(`"acct:a#1/address"`), []byte(`"zz"`), 1)),
		"null scopes":    resealForTest(bytes.Replace(body, []byte(`{"scopes":[]}`), []byte(`{"scopes":null}`), 1)),
		"future version": resealForTest(bytes.Replace(body, []byte(`"v":1`), []byte(`"v":2`), 1)),
	} {
		if _, err := UnmarshalScheduleState(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

// Random queues keep the scheduler's promises: no candidate twice, waiting
// candidates never, budgets and the member bound held, reserved turns only
// for eligible candidates, deficits within the bound, and the same answer
// whatever the input order.
func TestScheduleRandomInvariants(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	st := ScheduleState{}
	for round := 0; round < 400; round++ {
		var items []ScheduleItem
		for i := 0; i < r.IntN(40); i++ {
			class := Class(1 + r.IntN(3))
			it := ScheduleItem{ID: CandidateID(fmt.Sprintf("r%d-%d", round, i)), Scope: fmt.Sprintf("s%d", r.IntN(5)), Tier: Tier{class, Severity(1 + r.IntN(3))},
				Queued: t0.Add(time.Duration(r.IntN(100)) * time.Second), Cost: uint32(1 + r.IntN(4)), Ready: r.IntN(5) != 0}
			if class == ClassC3 {
				it.Direct = r.IntN(3) == 0
				it.Corroborated = !it.Direct && r.IntN(2) == 0
			}
			items = append(items, it)
		}
		lim := ScheduleLimits{General: uint32(r.IntN(20)), Reserved: uint32(r.IntN(10)), Members: 1 + r.IntN(MaxBatchMembers)}
		picks, next, err := Schedule(items, st, lim)
		if err != nil {
			t.Fatal(err)
		}
		byID := map[CandidateID]ScheduleItem{}
		for _, it := range items {
			byID[it.ID] = it
		}
		seen := map[CandidateID]bool{}
		var general, reserved uint32
		for _, p := range picks {
			it := byID[p.ID]
			if seen[p.ID] || !it.Ready || p.Cost != it.Cost {
				t.Fatalf("round %d: bad pick %+v", round, p)
			}
			seen[p.ID] = true
			switch p.Lane {
			case LaneGeneral:
				general += p.Cost
			case LaneDirect, LaneCorroborated:
				reserved += p.Cost
				if (p.Lane == LaneDirect) != it.Direct || (p.Lane == LaneCorroborated) != it.Corroborated {
					t.Fatalf("round %d: reserved turn for the wrong evidence: %+v", round, p)
				}
			}
		}
		if len(picks) > lim.Members || general > lim.General || reserved > lim.Reserved {
			t.Fatalf("round %d: bounds broken: %d picks, %d/%d units", round, len(picks), general, reserved)
		}
		if err = next.validate(); err != nil {
			t.Fatalf("round %d: state %v", round, err)
		}
		shuffled := append([]ScheduleItem(nil), items...)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		again, _, _ := Schedule(shuffled, st, lim)
		if !reflect.DeepEqual(again, picks) {
			t.Fatalf("round %d: input order changed the picks", round)
		}
		st = next
	}
}

func bytesItem(id, scope string, bytes uint32) ScheduleItem {
	it := schedItem(id, scope, ClassC2, SeverityHigh, time.Hour)
	it.Bytes = bytes
	return it
}

// History bytes rotate across scopes like block units: a scope earns
// HistoryQuantum bytes per visit toward its head, so large records wait for
// their turn and cannot take more than their share from small ones.
func TestScheduleHistoryBytesRotateFairly(t *testing.T) {
	items := []ScheduleItem{bytesItem("a1", "a", 4*HistoryQuantum)}
	for i := 0; i < 8; i++ {
		items = append(items, bytesItem(fmt.Sprintf("b%d", i), "b", 2000))
	}
	lim := ScheduleLimits{General: 100, GeneralBytes: 1 << 20, Members: 5}
	picks, st := mustSchedule(t, items, ScheduleState{}, lim)
	if got := picked(picks); !reflect.DeepEqual(got, []string{"b0", "b1", "b2", "a1", "b3"}) {
		t.Fatalf("picks = %v", got)
	}
	for _, p := range picks {
		want := uint32(2000)
		if p.ID == "a1" {
			want = 4 * HistoryQuantum
		}
		if p.Bytes != want {
			t.Fatalf("pick %s carries %d bytes, want %d", p.ID, p.Bytes, want)
		}
	}
	// b keeps the bytes it earned beyond its heads; a spent all of its own.
	if turn := st.Rings[ringC2].Scopes["b"]; turn.Bytes != 192 {
		t.Fatalf("b's earned bytes = %+v, want 192", turn)
	}
	if _, kept := st.Rings[ringC2].Scopes["a"]; kept {
		t.Fatal("a scope without work kept its turn")
	}
}

// A scope that earned its turn but finds too little history budget left
// holds the lane, and the next schedule serves it before cheaper work.
func TestScheduleHistoryBudgetHoldsAnEarnedTurn(t *testing.T) {
	items := []ScheduleItem{bytesItem("big", "a", 10000)}
	for i := 0; i < 6; i++ {
		items = append(items, bytesItem(fmt.Sprintf("s%d", i), "b", 1000))
	}
	picks, st := mustSchedule(t, items, ScheduleState{}, ScheduleLimits{General: 100, GeneralBytes: 9500, Members: MaxBatchMembers})
	if got := picked(picks); !reflect.DeepEqual(got, []string{"s0", "s1"}) {
		t.Fatalf("first batch = %v", got)
	}
	if st.ClassSlot != 4 {
		t.Fatalf("the held class slot = %d, want the C2 slot", st.ClassSlot)
	}
	var rest []ScheduleItem
	for _, it := range items {
		if it.ID != "s0" && it.ID != "s1" {
			rest = append(rest, it)
		}
	}
	picks, _ = mustSchedule(t, rest, st, ScheduleLimits{General: 100, GeneralBytes: 10000, Members: MaxBatchMembers})
	if got := picked(picks); len(got) == 0 || got[0] != "big" {
		t.Fatalf("cheaper work took the held turn: %v", got)
	}
	// Spent history budget ends the lane at the next earned head.
	picks, _ = mustSchedule(t, items[1:], ScheduleState{}, ScheduleLimits{General: 100, GeneralBytes: 3000, Members: MaxBatchMembers})
	if got := picked(picks); !reflect.DeepEqual(got, []string{"s0", "s1", "s2"}) {
		t.Fatalf("a spent budget = %v", got)
	}
}

// A head still earning its bytes does not hold the lane: work that costs
// no history keeps being served until the large head has earned its turn.
func TestScheduleEarningHeadDoesNotHold(t *testing.T) {
	items := []ScheduleItem{bytesItem("big", "a", 10000)}
	for i := 0; i < 4; i++ {
		items = append(items, bytesItem(fmt.Sprintf("free%d", i), "b", 0))
	}
	picks, _ := mustSchedule(t, items, ScheduleState{}, ScheduleLimits{General: 100, Members: MaxBatchMembers})
	if got := picked(picks); !reflect.DeepEqual(got, []string{"free0", "free1"}) {
		t.Fatalf("picks = %v", got)
	}
}

// The reserved lane holds its sub-lane's turn the same way.
func TestScheduleReservedHistoryHold(t *testing.T) {
	big := bytesItem("big", "a", 3*HistoryQuantum)
	big.Tier.Class, big.Corroborated = ClassC3, true
	small := bytesItem("small", "b", 1000)
	small.Tier.Class, small.Direct = ClassC3, true
	st := ScheduleState{NextCorroborated: true}
	st.Rings[ringCorroborated] = Ring{Scopes: map[string]ScopeTurn{"a": {Bytes: 3 * HistoryQuantum}}}
	lim := ScheduleLimits{Reserved: 10, ReservedBytes: 2000, Members: MaxBatchMembers}
	picks, next := mustSchedule(t, []ScheduleItem{big, small}, st, lim)
	if len(picks) != 0 || !next.NextCorroborated {
		t.Fatalf("a held corroborated turn = %v, next corroborated %t", picked(picks), next.NextCorroborated)
	}
	lim.ReservedBytes = 3 * HistoryQuantum
	picks, _ = mustSchedule(t, []ScheduleItem{big, small}, next, lim)
	if got := picked(picks); len(got) == 0 || got[0] != "big" || picks[0].Lane != LaneCorroborated {
		t.Fatalf("after the refill = %v", picks)
	}
}

// Earned bytes stop at the largest cost, even with bytes left over from
// earlier heads.
func TestScheduleEarnedBytesAreBounded(t *testing.T) {
	st := ScheduleState{}
	st.Rings[ringC2] = Ring{Scopes: map[string]ScopeTurn{"a": {Bytes: 30000}}}
	head := bytesItem("max", "a", MaxHistoryBytes)
	head.Cost = 2
	items := []ScheduleItem{head, bytesItem("other", "b", 0)}
	_, next := mustSchedule(t, items, st, ScheduleLimits{General: 100, Members: MaxBatchMembers})
	if turn := next.Rings[ringC2].Scopes["a"]; turn.Bytes != MaxHistoryBytes {
		t.Fatalf("earned bytes = %+v, want the bound", turn)
	}
	data, err := next.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := UnmarshalScheduleState(data); err != nil || back.Rings[ringC2].Scopes["a"] != next.Rings[ringC2].Scopes["a"] {
		t.Fatalf("earned bytes did not round trip: %+v, %v", back.Rings[ringC2].Scopes["a"], err)
	}
	over := ScheduleState{}
	over.Rings[ringC2] = Ring{Scopes: map[string]ScopeTurn{"a": {Bytes: MaxHistoryBytes + 1}}}
	if _, err := over.MarshalBinary(); err == nil {
		t.Fatal("encoded earned bytes over the bound")
	}
	if _, _, err := Schedule([]ScheduleItem{bytesItem("x", "a", MaxHistoryBytes+1)}, ScheduleState{}, wide); err == nil {
		t.Fatal("accepted an item over the largest history cost")
	}
}

// Random queues keep every history budget, with byte costs and budgets.
func TestScheduleRandomHistoryBudgets(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	st := ScheduleState{}
	for round := 0; round < 400; round++ {
		var items []ScheduleItem
		for i := 0; i < r.IntN(40); i++ {
			class := Class(1 + r.IntN(3))
			it := ScheduleItem{ID: CandidateID(fmt.Sprintf("r%d-%d", round, i)), Scope: fmt.Sprintf("s%d", r.IntN(5)), Tier: Tier{class, Severity(1 + r.IntN(3))},
				Queued: t0.Add(time.Duration(r.IntN(100)) * time.Second), Cost: 1, Bytes: uint32(r.IntN(MaxHistoryBytes + 1)), Ready: true}
			if class == ClassC3 {
				it.Direct = r.IntN(3) == 0
				it.Corroborated = !it.Direct && r.IntN(2) == 0
			}
			items = append(items, it)
		}
		lim := ScheduleLimits{General: uint32(r.IntN(20)), Reserved: uint32(r.IntN(10)), Members: MaxBatchMembers,
			GeneralBytes: uint64(r.IntN(3 * MaxHistoryBytes)), ReservedBytes: uint64(r.IntN(2 * MaxHistoryBytes))}
		picks, next, err := Schedule(items, st, lim)
		if err != nil {
			t.Fatal(err)
		}
		var general, reserved uint64
		for _, p := range picks {
			if p.Lane == LaneGeneral {
				general += uint64(p.Bytes)
			} else {
				reserved += uint64(p.Bytes)
			}
		}
		if general > lim.GeneralBytes || reserved > lim.ReservedBytes {
			t.Fatalf("round %d: history budgets broken: %d/%d, %d/%d", round, general, lim.GeneralBytes, reserved, lim.ReservedBytes)
		}
		if err = next.validate(); err != nil {
			t.Fatalf("round %d: state %v", round, err)
		}
		st = next
	}
}

// General and reserved picks share one finite recovery allowance.
func TestScheduleRecoveryBudgetSharedByLanes(t *testing.T) {
	items := []ScheduleItem{
		{ID: "direct", Scope: "a", Tier: Tier{Class: ClassC3, Severity: SeverityCritical}, Direct: true, Cost: 1, Recovery: 3000, Ready: true},
		{ID: "general", Scope: "b", Tier: Tier{Class: ClassC1, Severity: SeverityHigh}, Cost: 1, Recovery: 3000, Ready: true},
	}
	picks, _, err := Schedule(items, ScheduleState{}, ScheduleLimits{General: 1, Reserved: 1, Members: 2, RecoveryBytes: 3000})
	if err != nil || len(picks) != 1 || picks[0].ID != "direct" {
		t.Fatalf("shared recovery picks: %+v %v", picks, err)
	}
	items[0].Recovery = MaxHistoryBytes + 1
	if _, _, err = Schedule(items, ScheduleState{}, ScheduleLimits{General: 1, Reserved: 1, Members: 2, RecoveryBytes: 3000}); err == nil {
		t.Fatal("accepted an oversized recovery cost")
	}
}

func TestScheduleStorageHoldKeepsEarnedCredit(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%t", recovery), func(t *testing.T) {
			head := bytesItem("head", "c", HistoryQuantum)
			lim := ScheduleLimits{General: 1, Members: 1}
			if recovery {
				head.Recovery = HistoryQuantum
				lim.GeneralBytes = HistoryQuantum
			}
			picks, next := mustSchedule(t, []ScheduleItem{head}, ScheduleState{}, lim)
			if len(picks) != 0 {
				t.Fatalf("picked a head without storage: %v", picks)
			}
			want := ScopeTurn{Deficit: 1, Bytes: HistoryQuantum}
			if got := next.Rings[ringC2].Scopes["c"]; got != want {
				t.Fatalf("held turn lost earned credit: %+v, want %+v", got, want)
			}
			data, err := next.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			back, err := UnmarshalScheduleState(data)
			if err != nil || back.Rings[ringC2].Scopes["c"] != want {
				t.Fatalf("held credit did not survive a reopen: %+v, %v", back, err)
			}
			// A held cursor must name a scope with an earned turn.
			body := data[:len(data)-8]
			for _, scope := range []string{"missing", "bad scope"} {
				bad := bytes.Replace(body, []byte(`"held":"c"`), []byte(fmt.Sprintf(`"held":%q`, scope)), 1)
				if bytes.Equal(body, bad) {
					t.Fatal("held scope was not persisted")
				}
				if _, err := UnmarshalScheduleState(resealForTest(bad)); err != ErrCorruptRecord {
					t.Fatalf("accepted a malformed held scope: %v", err)
				}
			}
			bad := bytes.Replace(body, []byte(`,"deficit":1`), nil, 1)
			if _, err := UnmarshalScheduleState(resealForTest(bad)); err != ErrCorruptRecord {
				t.Fatalf("accepted a hold without earned units: %v", err)
			}
		})
	}
}

func TestScheduleStorageHoldPrecedesNewScopes(t *testing.T) {
	for _, lane := range []Lane{LaneGeneral, LaneDirect, LaneCorroborated} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovery=%t", lane, recovery), func(t *testing.T) {
				first := bytesItem("first", "a", 1)
				head := bytesItem("head", "c", HistoryQuantum)
				arrival := bytesItem("arrival", "b", 1)
				lim := ScheduleLimits{General: 10, GeneralBytes: HistoryQuantum, Members: MaxBatchMembers}
				for _, it := range []*ScheduleItem{&first, &head, &arrival} {
					if lane != LaneGeneral {
						it.Tier.Class = ClassC3
						it.Direct, it.Corroborated = lane == LaneDirect, lane == LaneCorroborated
					}
					if recovery {
						it.Recovery, it.Bytes = it.Bytes, 0
					}
				}
				if lane != LaneGeneral {
					lim.General, lim.Reserved = 0, lim.General
					lim.ReservedBytes = lim.GeneralBytes
				}
				if recovery {
					lim.RecoveryBytes = HistoryQuantum
				}
				picks, next := mustSchedule(t, []ScheduleItem{first, head}, ScheduleState{}, lim)
				if got := picked(picks); !reflect.DeepEqual(got, []string{"first"}) {
					t.Fatalf("first batch = %v", got)
				}
				data, err := next.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				next, err = UnmarshalScheduleState(data)
				if err != nil {
					t.Fatal(err)
				}
				picks, _ = mustSchedule(t, []ScheduleItem{arrival, head}, next, lim)
				if got := picked(picks); !reflect.DeepEqual(got, []string{"head"}) || picks[0].Lane != lane {
					t.Fatalf("new scope took the held budget: %v", picks)
				}
				// A hold ends when its scope has no ready work, including
				// after the head is removed or starts a retry wait.
				head.Ready = false
				for _, items := range [][]ScheduleItem{{arrival}, {arrival, head}} {
					picks, cleared := mustSchedule(t, items, next, lim)
					if got := picked(picks); !reflect.DeepEqual(got, []string{"arrival"}) {
						t.Fatalf("absent head held the lane: %v", got)
					}
					if _, err := cleared.MarshalBinary(); err != nil {
						t.Fatalf("cleared hold is not persistable: %v", err)
					}
				}
			})
		}
	}
}
