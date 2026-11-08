package admission

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

// boundRun serves one member per call under a continuous flood: every
// pick of a flood member is replaced at once by a newer member of the same
// scope and tier. It returns the call that served target, or 0.
func boundRun(t *testing.T, items []ScheduleItem, target CandidateID, lim ScheduleLimits, calls int) int {
	t.Helper()
	st := ScheduleState{}
	next := 0
	for call := 1; call <= calls; call++ {
		picks, after := mustSchedule(t, items, st, lim)
		if len(picks) != 1 {
			t.Fatalf("call %d picked %d members", call, len(picks))
		}
		var pickedItem ScheduleItem
		for _, it := range items {
			if it.ID == picks[0].ID {
				pickedItem = it
			}
		}
		ring := int(pickedItem.Tier.Class - ClassC1)
		switch picks[0].Lane {
		case LaneDirect:
			ring = ringDirect
		case LaneCorroborated:
			ring = ringCorroborated
		}
		if pickedItem.ID == "" || picks[0].Cost != 1 || after.Rings[ring].Last != pickedItem.Scope {
			t.Fatalf("opportunity %d: pick %+v, cursor %q, item %+v", call, picks[0], after.Rings[ring].Last, pickedItem)
		}
		if picks[0].ID == target {
			return call
		}
		for i, it := range items {
			if it.ID == picks[0].ID {
				next++
				it.ID = CandidateID(fmt.Sprintf("%s-n%06d", it.Scope, next))
				it.Queued = t0.Add(time.Duration(call) * time.Second)
				items[i] = it
				break
			}
		}
		data, err := after.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if st, err = UnmarshalScheduleState(data); err != nil {
			t.Fatal(err)
		}
	}
	return 0
}

// A continuously eligible new member is served within the spec 7.1 bound
// whatever floods the other scopes and tiers send: 7*7*S*M*(W+Q+1) general
// turns, or 2*7*S*M*(W+Q+1) reserved ones, with M = 1 and Q = 0.
func TestScheduleServesANewMemberWithinTheBound(t *testing.T) {
	classes := []Class{ClassC1, ClassC2, ClassC3}
	sevs := []Severity{SeverityWarning, SeverityHigh, SeverityCritical}
	for seed := uint64(1); seed <= 8; seed++ {
		for _, reserved := range []bool{false, true} {
			t.Run(fmt.Sprintf("seed%d/reserved=%t", seed, reserved), func(t *testing.T) {
				rng := rand.New(rand.NewPCG(seed, 7))
				s := 2 + rng.IntN(23)
				w := rng.IntN(4)
				var items []ScheduleItem
				add := func(id, scope string, c Class, sev Severity, age time.Duration, direct bool) {
					it := schedItem(id, scope, c, sev, age)
					if reserved {
						it.Tier.Class = ClassC3
						it.Direct, it.Corroborated = direct, !direct
					}
					items = append(items, it)
				}
				for i := 0; i < s; i++ {
					scope := fmt.Sprintf("scope%02d", i)
					for _, c := range classes {
						for _, sev := range sevs {
							add(fmt.Sprintf("%s-%s-%s", scope, c, sev), scope, c, sev, time.Hour, true)
							add(fmt.Sprintf("%s-%s-%s-k", scope, c, sev), scope, c, sev, time.Hour, false)
						}
					}
				}
				// The target scope is scope00: W older members of its tier
				// stand ahead of the target.
				for i := 0; i < w; i++ {
					add(fmt.Sprintf("ahead-%d", i), "scope00", ClassC1, SeverityWarning, 2*time.Hour+time.Duration(i)*time.Minute, false)
				}
				add("target", "scope00", ClassC1, SeverityWarning, 30*time.Minute, false)
				target := items[len(items)-1]
				// A newer member of its tier queues behind the target.
				add("behind", "scope00", ClassC1, SeverityWarning, time.Minute, false)
				// W counts every member of the target's scope, tier and
				// sub-lane queued before it, flood members included.
				ahead := 0
				for _, it := range items[:len(items)-2] {
					if it.Scope == target.Scope && it.Tier == target.Tier && (!reserved || it.Direct == target.Direct) && it.Queued.Before(target.Queued) {
						ahead++
					}
				}
				lim, bound := ScheduleLimits{General: 1, Members: 1}, 7*7*s*(ahead+1)
				if reserved {
					lim, bound = ScheduleLimits{Reserved: 1, Members: 1}, 2*7*s*(ahead+1)
				}
				// The members ahead are replaced too; only the target is
				// not, so it must come up within the bound.
				if call := boundRun(t, items, "target", lim, bound); call == 0 {
					t.Fatalf("S=%d W=%d: target not served within %d calls", s, ahead, bound)
				}
			})
		}
	}
}

// Each of S scopes flooding one tier is served once in every S
// consecutive single-member calls (spec 7.1: a turn within S scope-rotation
// turns), across checkpoints as after a ledger reopen.
func TestScheduleServesEveryScopeOncePerRotation(t *testing.T) {
	for _, s := range []int{2, 3, 7, 40} {
		t.Run(fmt.Sprint(s), func(t *testing.T) {
			var items []ScheduleItem
			for i := 0; i < s; i++ {
				for j := 0; j < 3; j++ {
					items = append(items, schedItem(fmt.Sprintf("s%02d-%d", i, j), fmt.Sprintf("s%02d", i), ClassC2, SeverityHigh, time.Hour))
				}
			}
			st := ScheduleState{}
			var order []string
			scopeOf := map[CandidateID]string{}
			for _, it := range items {
				scopeOf[it.ID] = it.Scope
			}
			for call := 0; call < 3*s; call++ {
				picks, next := mustSchedule(t, items, st, ScheduleLimits{General: 1, Members: 1})
				if len(picks) != 1 {
					t.Fatalf("call %d picked %d", call, len(picks))
				}
				order = append(order, scopeOf[picks[0].ID])
				kept := items[:0]
				for _, it := range items {
					if it.ID != picks[0].ID {
						kept = append(kept, it)
					}
				}
				items = kept
				data, err := next.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if st, err = UnmarshalScheduleState(data); err != nil {
					t.Fatal(err)
				}
			}
			for start := 0; start+s <= len(order); start++ {
				seen := map[string]bool{}
				for _, scope := range order[start : start+s] {
					if seen[scope] {
						t.Fatalf("scope %s served twice in one rotation: %v", scope, order)
					}
					seen[scope] = true
				}
			}
		})
	}
}
