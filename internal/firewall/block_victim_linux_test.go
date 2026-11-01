//go:build linux

package firewall

import (
	"fmt"
	"testing"
	"time"
)

// victimAction is a well-formed admission action ID.
func victimAction(n int) string { return fmt.Sprintf("act_%032x", n) }

// newVictimFixture is a batch fixture whose temporary set of two is full:
// a verified admission block, the victim the ledger claimed, and an
// operator tempban, which is never a victim.
func newVictimFixture(t *testing.T) (*batchFixture, BlockVictim) {
	t.Helper()
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	victim := BlockVictim{Action: victimAction(1), IP: "203.0.113.60", ExpiresAt: at.Add(time.Hour)}
	f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{
		{IP: victim.IP, Reason: "CSM auto-block: test", Source: SourceAutoResponse, BlockedAt: at.Add(-time.Hour), ExpiresAt: victim.ExpiresAt, ActionID: victim.Action},
		{IP: "203.0.113.61", Reason: "operator", ExpiresAt: at.Add(time.Hour)},
	}})
	f.e.cfg.DenyTempIPLimit = 2
	f.live[victim.IP], f.live["203.0.113.61"] = time.Hour, time.Hour
	return f, victim
}

// evicting is a member that takes victim's slot.
func (f *batchFixture) evicting(action, ip string, victim BlockVictim) BlockMember {
	m := f.member(action, ip)
	m.Victim = victim
	return m
}

// checkMembers runs the apply's member check on one fresh snapshot.
func (f *batchFixture) checkMembers(t *testing.T, members []BlockMember) ([]BlockRefusal, []bool) {
	t.Helper()
	verified := f.e.verifiedRanges(members)
	f.e.mu.Lock()
	defer f.e.mu.Unlock()
	snap, err := f.e.blockSnapshotLocked()
	if err != nil {
		t.Fatal(err)
	}
	evicts := f.e.victimsLocked(members, snap)
	return f.e.checkBlockMembersLocked(members, verified, snap, snap.at, evicts), evicts
}

// A member whose victim still qualifies takes the victim's slot in a full
// set; a member without one needs a free slot.
func TestBlockMembersTakeTheirVictimsSlot(t *testing.T) {
	f, victim := newVictimFixture(t)
	refusals, evicts := f.checkMembers(t, []BlockMember{
		f.member("act_free", "203.0.113.20"),
		f.evicting("act_evict", "203.0.113.21", victim),
	})
	if fmt.Sprint(refusals) != fmt.Sprint([]BlockRefusal{BlockRefusedFull, ""}) || fmt.Sprint(evicts) != "[false true]" {
		t.Fatalf("refusals %q, evicts %v", refusals, evicts)
	}
}

// The engine removes only the admission block the ledger claimed, as it
// still is. Anything else leaves the member needing a free slot; a victim
// whose element is gone left one.
func TestBlockVictimMustStillQualify(t *testing.T) {
	// victimRow rewrites the victim's row; the operator's tempban stays.
	victimRow := func(t *testing.T, f *batchFixture, row BlockedEntry) {
		writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row, {IP: "203.0.113.61", Reason: "operator", ExpiresAt: f.at.Add(time.Hour)}}})
	}
	for name, tc := range map[string]struct {
		victim func(BlockVictim) BlockVictim
		state  func(*testing.T, *batchFixture)
		want   BlockRefusal
	}{
		"another action":          {victim: func(v BlockVictim) BlockVictim { v.Action = victimAction(2); return v }, want: BlockRefusedFull},
		"another expiry":          {victim: func(v BlockVictim) BlockVictim { v.ExpiresAt = v.ExpiresAt.Add(time.Second); return v }, want: BlockRefusedFull},
		"no expiry":               {victim: func(v BlockVictim) BlockVictim { v.ExpiresAt = time.Time{}; return v }, want: BlockRefusedFull},
		"a non-canonical address": {victim: func(v BlockVictim) BlockVictim { v.IP = "::ffff:203.0.113.60"; return v }, want: BlockRefusedFull},
		"the operator's tempban":  {victim: func(v BlockVictim) BlockVictim { v.IP = "203.0.113.61"; return v }, want: BlockRefusedFull},
		"a permanent element":     {state: func(_ *testing.T, f *batchFixture) { f.live["203.0.113.60"] = 0 }, want: BlockRefusedFull},
		"an unproven lifetime":    {state: func(_ *testing.T, f *batchFixture) { f.expires["203.0.113.60"] = 10 * time.Minute }, want: BlockRefusedFull},
		"an element gone":         {state: func(_ *testing.T, f *batchFixture) { delete(f.live, "203.0.113.60") }, want: ""},
		"an unverified row": {state: func(_ *testing.T, f *batchFixture) {
			f.e.mu.Lock()
			f.e.unverifiedBlockActions = map[string]bool{victimAction(1): true}
			f.e.mu.Unlock()
		}, want: BlockRefusedFull},
		"a row with a malformed action": {
			state: func(t *testing.T, f *batchFixture) {
				victimRow(t, f, BlockedEntry{IP: "203.0.113.60", Reason: "auto", Source: SourceAutoResponse, ExpiresAt: f.at.Add(time.Hour), ActionID: "act_victim"})
			},
			victim: func(v BlockVictim) BlockVictim { v.Action = "act_victim"; return v },
			want:   BlockRefusedFull,
		},
		"a permanent admission row": {
			state: func(t *testing.T, f *batchFixture) {
				victimRow(t, f, BlockedEntry{IP: "203.0.113.60", Reason: "auto", Source: SourceAutoResponse, ActionID: victimAction(1)})
				f.live["203.0.113.60"] = 0
			},
			victim: func(v BlockVictim) BlockVictim { v.ExpiresAt = time.Time{}; return v },
			want:   "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, victim := newVictimFixture(t)
			if tc.state != nil {
				tc.state(t, f)
			}
			if tc.victim != nil {
				victim = tc.victim(victim)
			}
			refusals, evicts := f.checkMembers(t, []BlockMember{f.evicting("act_evict", "203.0.113.21", victim)})
			if refusals[0] != tc.want || evicts[0] {
				t.Fatalf("refusal %q, evicts %v; want %q without the victim", refusals[0], evicts[0], tc.want)
			}
		})
	}
}

// A member that takes its victim's slot leaves the free slots to the
// members after it.
func TestBlockVictimSlotLeavesTheFreeSlots(t *testing.T) {
	f, victim := newVictimFixture(t)
	f.e.cfg.DenyTempIPLimit = 3
	refusals, evicts := f.checkMembers(t, []BlockMember{
		f.evicting("act_evict", "203.0.113.21", victim),
		f.member("act_free", "203.0.113.20"),
		f.member("act_full", "203.0.113.22"),
	})
	if fmt.Sprint(refusals) != fmt.Sprint([]BlockRefusal{"", "", BlockRefusedFull}) || fmt.Sprint(evicts) != "[true false false]" {
		t.Fatalf("refusals %q, evicts %v", refusals, evicts)
	}
}

// One victim funds one member: a second member naming it needs a free
// slot.
func TestBlockVictimIsTakenOnce(t *testing.T) {
	f, victim := newVictimFixture(t)
	refusals, evicts := f.checkMembers(t, []BlockMember{
		f.evicting("act_one", "203.0.113.21", victim),
		f.evicting("act_two", "203.0.113.22", victim),
	})
	if fmt.Sprint(refusals) != fmt.Sprint([]BlockRefusal{"", BlockRefusedFull}) || fmt.Sprint(evicts) != "[true false]" {
		t.Fatalf("refusals %q, evicts %v", refusals, evicts)
	}
}

// A victim at an address the batch targets is never removed: the batch
// would delete and add the same element.
func TestBlockVictimNeverAtAMembersAddress(t *testing.T) {
	f, victim := newVictimFixture(t)
	refusals, evicts := f.checkMembers(t, []BlockMember{
		f.evicting("act_one", "203.0.113.21", victim),
		f.member("act_two", victim.IP),
	})
	if fmt.Sprint(refusals) != fmt.Sprint([]BlockRefusal{BlockRefusedFull, BlockRefusedExisting}) || fmt.Sprint(evicts) != "[false false]" {
		t.Fatalf("refusals %q, evicts %v", refusals, evicts)
	}
}

// A replacement cannot leave the complete set above its current limit.
// The operator may lower the limit or add a block after reservation.
func TestBlockVictimCannotFundAnOverfullSet(t *testing.T) {
	f, victim := newVictimFixture(t)
	f.e.cfg.DenyTempIPLimit = 1
	member := f.evicting("act_evict", "203.0.113.21", victim)
	refusals, evicts := f.checkMembers(t, []BlockMember{member})
	if len(refusals) != 1 || refusals[0] != BlockRefusedFull || !evicts[0] {
		t.Fatalf("overfull replacement: refusals %q, evicts %v", refusals, evicts)
	}
	results, err := f.e.ApplyBlockBatch([]BlockMember{member})
	if err != nil || effects(results) != "failed/set_full" {
		t.Fatalf("overfull apply: %+v, %v", results, err)
	}
	if _, held := f.live[victim.IP]; !held {
		t.Fatal("an overfull set lost its victim")
	}
}
