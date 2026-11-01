package admission

import "testing"

// Lane readiness must preserve membership and earned scope turns. A
// blocked reserved turn can still use a funded general turn.
func TestScheduleSlotReadinessKeepsScopeTurns(t *testing.T) {
	it := schedItem("waiting", "scope", ClassC3, SeverityCritical, 0)
	it.Direct = true
	it.BlockedGeneral, it.BlockedReserved = true, true
	st := ScheduleState{}
	turn := ScopeTurn{Deficit: 3, Bytes: 123, Severity: 2}
	st.Rings[ringC3].Scopes = map[string]ScopeTurn{it.Scope: turn}
	st.Rings[ringDirect].Scopes = map[string]ScopeTurn{it.Scope: turn}
	picks, next := mustSchedule(t, []ScheduleItem{it}, st, wide)
	if len(picks) != 0 || next.Rings[ringC3].Scopes[it.Scope] != turn || next.Rings[ringDirect].Scopes[it.Scope] != turn {
		t.Fatalf("blocked work lost its turns: %+v %+v", picks, next)
	}
	it.BlockedGeneral = false
	picks, _ = mustSchedule(t, []ScheduleItem{it}, next, wide)
	if len(picks) != 1 || picks[0].ID != it.ID || picks[0].Lane != LaneGeneral {
		t.Fatalf("funded general turn was hidden: %+v", picks)
	}
	it.BlockedGeneral, it.BlockedReserved = true, false
	picks, _ = mustSchedule(t, []ScheduleItem{it}, next, wide)
	if len(picks) != 1 || picks[0].Lane != LaneDirect {
		t.Fatalf("funded reserved turn was hidden: %+v", picks)
	}
}
