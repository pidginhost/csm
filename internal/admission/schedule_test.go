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
