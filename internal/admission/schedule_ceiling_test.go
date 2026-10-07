package admission

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func challengeItem(id, scope string, class Class) ScheduleItem {
	it := schedItem(id, scope, class, SeverityHigh, 0)
	it.CeilingCost = 0
	it.Bytes = 1
	return it
}

func TestScheduleChallengeDoesNotNeedBlockCredit(t *testing.T) {
	for _, lane := range []Lane{LaneGeneral, LaneDirect, LaneCorroborated} {
		t.Run(lane.String(), func(t *testing.T) {
			paid := schedItem("paid", "same", ClassC2, SeverityHigh, time.Hour)
			free := challengeItem("challenge", "same", ClassC2)
			arrival := challengeItem("arrival", "new", ClassC3)
			lim := ScheduleLimits{Members: 2, GeneralBytes: 100, ReservedBytes: 100}
			if lane != LaneGeneral {
				paid.Tier.Class, free.Tier.Class = ClassC3, ClassC3
				paid.Direct, free.Direct = lane == LaneDirect, lane == LaneDirect
				paid.Corroborated, free.Corroborated = lane == LaneCorroborated, lane == LaneCorroborated
				arrival.Direct = lane == LaneDirect
				arrival.Corroborated = lane == LaneCorroborated
			}
			picks, st := mustSchedule(t, []ScheduleItem{paid, free}, ScheduleState{}, lim)
			if !reflect.DeepEqual(picked(picks), []string{"challenge"}) || picks[0].Cost != 0 || picks[0].Lane != lane {
				t.Fatalf("zero ceiling picks: %+v", picks)
			}
			data, err := st.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			st, err = UnmarshalScheduleState(data)
			if err != nil {
				t.Fatal(err)
			}
			lim.Members = 1
			if lane == LaneGeneral {
				lim.General = 1
			} else {
				lim.Reserved = 1
			}
			picks, _ = mustSchedule(t, []ScheduleItem{paid, arrival}, st, lim)
			if !reflect.DeepEqual(picked(picks), []string{"paid"}) {
				t.Fatalf("recovered paid turn: %+v", picks)
			}
		})
	}
}

func TestScheduleFreeTrafficKeepsFairTurnsAndPaidRecovery(t *testing.T) {
	paid := schedItem("paid", "held", ClassC1, SeverityHigh, time.Hour)
	st := ScheduleState{}
	counts := map[Class]int{}
	for n := 0; n < 70; n++ {
		items := []ScheduleItem{paid}
		byID := map[CandidateID]Class{}
		for _, class := range []Class{ClassC3, ClassC2, ClassC1} {
			it := challengeItem(fmt.Sprintf("free-%d-%s", n, class), "free", class)
			byID[it.ID] = class
			items = append(items, it)
		}
		picks, next := mustSchedule(t, items, st, ScheduleLimits{Members: 1, GeneralBytes: 100})
		if len(picks) != 1 || picks[0].Cost != 0 {
			t.Fatalf("round %d: %+v", n, picks)
		}
		counts[byID[picks[0].ID]]++
		st = next
	}
	if counts[ClassC3] != 40 || counts[ClassC2] != 20 || counts[ClassC1] != 10 {
		t.Fatalf("free class turns: %v", counts)
	}
	data, err := st.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	st, err = UnmarshalScheduleState(data)
	if err != nil {
		t.Fatal(err)
	}
	picks, _ := mustSchedule(t, []ScheduleItem{paid, challengeItem("new", "free", ClassC3)}, st, ScheduleLimits{General: 1, Members: 1, GeneralBytes: 100})
	if !reflect.DeepEqual(picked(picks), []string{"paid"}) {
		t.Fatalf("free traffic took recovered credit: %+v", picks)
	}
}

func TestScheduleChallengeKeepsHistoryAndRecoveryPromises(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%t", recovery), func(t *testing.T) {
			paid := schedItem("paid", "same", ClassC2, SeverityHigh, time.Hour)
			paid.Bytes = 1
			large := challengeItem("large", "same", ClassC2)
			large.Bytes = 10000
			lim := ScheduleLimits{Members: 2, GeneralBytes: 8000, RecoveryBytes: 200}
			if recovery {
				large.Bytes, large.Recovery = 1, 100
				lim.GeneralBytes, lim.RecoveryBytes = 100, 20
			}
			_, st := mustSchedule(t, []ScheduleItem{paid, large}, ScheduleState{}, lim)
			if st.GeneralHold == nil || st.GeneralHold.ID != paid.ID || st.Rings[ringC2].Held != "same" {
				t.Fatalf("independent promises: %+v", st)
			}
			earned := st.Rings[ringC2].Scopes["same"]
			for n := 0; n < 3; n++ {
				arrival := challengeItem(fmt.Sprintf("arrival-%d", n), "new", ClassC3)
				lim.General = 1
				picks, next := mustSchedule(t, []ScheduleItem{paid, large, arrival}, st, lim)
				if len(picks) != 0 || next.GeneralHold == nil || next.Rings[ringC2].Held != "same" || next.Rings[ringC2].Scopes["same"].Bytes != earned.Bytes || next.Rings[ringC2].Scopes["same"].Deficit < earned.Deficit {
					t.Fatalf("promised bytes lent: %+v, %+v", picks, next)
				}
				st = next
			}
			lim.GeneralBytes, lim.RecoveryBytes = 12000, 200
			picks, _ := mustSchedule(t, []ScheduleItem{paid, large, challengeItem("arrival", "new", ClassC3)}, st, lim)
			if !reflect.DeepEqual(picked(picks), []string{"large", "paid"}) {
				t.Fatalf("fulfilled promises: %+v", picks)
			}
		})
	}
}

func TestScheduleCeilingHoldsAreBoundedAndCopied(t *testing.T) {
	paid := schedItem("paid", "same", ClassC2, SeverityHigh, time.Hour)
	free := challengeItem("free", "same", ClassC2)
	_, st := mustSchedule(t, []ScheduleItem{paid, free}, ScheduleState{}, ScheduleLimits{Members: 1, GeneralBytes: 100})
	if st.GeneralHold == nil {
		t.Fatal("charged turn not saved")
	}
	before := *st.GeneralHold
	_, _ = mustSchedule(t, []ScheduleItem{paid}, st, ScheduleLimits{General: 1, Members: 1, GeneralBytes: 100})
	if *st.GeneralHold != before {
		t.Fatal("schedule mutated caller's hold")
	}
	for _, bad := range []CeilingHold{
		{ID: "paid", Scope: "same", Ring: ringDirect},
		{ID: "paid", Scope: "same", Ring: ringC2, ClassSlot: 4, Slot: patternSlots},
		{ID: "paid", Scope: "same", Ring: ringC2, ClassSlot: 4, Turn: ScopeTurn{Deficit: MaxMemberCost + 1}},
		{ID: "paid", Scope: "same", Ring: ringC2, ClassSlot: 4, Turn: ScopeTurn{Bytes: MaxHistoryBytes + 1}},
	} {
		copy := st.clone()
		copy.GeneralHold = &bad
		if _, err := copy.MarshalBinary(); err == nil {
			t.Fatalf("encoded invalid ceiling hold: %+v", bad)
		}
	}
	waiting := paid
	waiting.Ready = false
	picks, next := mustSchedule(t, []ScheduleItem{waiting, challengeItem("other", "new", ClassC2)}, st, ScheduleLimits{General: 1, Members: 1, GeneralBytes: 100})
	if !reflect.DeepEqual(picked(picks), []string{"other"}) || next.GeneralHold != nil {
		t.Fatalf("backoff kept a ceiling promise: %+v %+v", picks, next)
	}
}

func TestScheduleChallengePreservesTheChargedHeadsEarnedHistory(t *testing.T) {
	paid := schedItem("paid", "same", ClassC2, SeverityHigh, time.Hour)
	paid.Cost, paid.CeilingCost, paid.Bytes = 3, 1, 10000
	free := challengeItem("free", "same", ClassC2)
	free.Bytes = 100
	earned := ScopeTurn{Severity: 4, Deficit: 2, Bytes: 12000}
	st := ScheduleState{}
	st.Rings[ringC2] = Ring{Held: "same", Scopes: map[string]ScopeTurn{"same": earned}}
	picks, next := mustSchedule(t, []ScheduleItem{paid, free}, st, ScheduleLimits{Members: 1, GeneralBytes: 100})
	if !reflect.DeepEqual(picked(picks), []string{"free"}) || next.GeneralHold == nil || next.GeneralHold.Turn != earned {
		t.Fatalf("charged history lent to challenge: %+v %+v", picks, next)
	}
	picks, _ = mustSchedule(t, []ScheduleItem{paid, challengeItem("new", "new", ClassC3)}, next, ScheduleLimits{General: 1, Members: 1, GeneralBytes: 11000})
	if !reflect.DeepEqual(picked(picks), []string{"paid"}) {
		t.Fatalf("charged history lost after recovery: %+v", picks)
	}
}

func TestScheduleChallengePreservesTheNextChargedScope(t *testing.T) {
	a := schedItem("paid-a", "a", ClassC2, SeverityHigh, time.Hour)
	b := schedItem("paid-b", "b", ClassC2, SeverityHigh, time.Hour)
	st := ScheduleState{}
	st.Rings[ringC2] = Ring{Last: "a"}
	picks, next := mustSchedule(t, []ScheduleItem{a, b, challengeItem("free", "free", ClassC2)}, st, ScheduleLimits{Members: 1, GeneralBytes: 100})
	if !reflect.DeepEqual(picked(picks), []string{"free"}) || next.GeneralHold == nil || next.GeneralHold.ID != b.ID {
		t.Fatalf("unfunded charged cursor changed: %+v %+v", picks, next)
	}
	picks, _ = mustSchedule(t, []ScheduleItem{a, b, challengeItem("arrival", "new", ClassC3)}, next, ScheduleLimits{General: 1, Members: 1, GeneralBytes: 100})
	if !reflect.DeepEqual(picked(picks), []string{"paid-b"}) {
		t.Fatalf("recovered scope turn changed: %+v", picks)
	}
}

func TestScheduleChallengePreservesTheLentChargedClassTurn(t *testing.T) {
	paid := schedItem("paid", "paid", ClassC2, SeverityHigh, time.Hour)
	free := challengeItem("free", "free", ClassC1)
	picks, next := mustSchedule(t, []ScheduleItem{paid, free}, ScheduleState{}, ScheduleLimits{Members: 1, GeneralBytes: 100})
	if !reflect.DeepEqual(picked(picks), []string{"free"}) || next.GeneralHold == nil || next.GeneralHold.ClassSlot != 4 {
		t.Fatalf("lent charged class turn changed: %+v %+v", picks, next)
	}
	peer := schedItem("peer", "peer", ClassC2, SeverityHigh, 0)
	picks, next = mustSchedule(t, []ScheduleItem{paid, peer, challengeItem("arrival", "new", ClassC3)}, next, ScheduleLimits{General: 1, Members: 1, GeneralBytes: 100})
	if !reflect.DeepEqual(picked(picks), []string{"paid"}) || next.ClassSlot != 5 {
		t.Fatalf("recovered class pattern changed: %+v %+v", picks, next)
	}
	picks, _ = mustSchedule(t, []ScheduleItem{peer, challengeItem("new-c3", "new", ClassC3)}, next, ScheduleLimits{General: 1, Members: 1, GeneralBytes: 100})
	if !reflect.DeepEqual(picked(picks), []string{"peer"}) {
		t.Fatalf("lent class lost its second quantum: %+v", picks)
	}
}
