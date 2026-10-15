package firewall

import (
	"fmt"
	"testing"
	"time"
)

func readyMember(action, ip string) BlockMember {
	return BlockMember{Action: action, IP: ip}
}

// Only the members a turn is ready to run take temporary slots, in order:
// a repeated address or action is a duplicate before it can take one, and
// the rest find the set full once the occupancy reaches the limit.
func TestBlockAdmissionReadyCapacityFillsInOrder(t *testing.T) {
	a := BlockAdmission{Temporary: 2, Limit: 4}
	got := a.ReadyCapacity([]BlockMember{
		readyMember("act_one", "203.0.113.20"),
		readyMember("act_two", "203.0.113.20"),
		readyMember("act_one", "203.0.113.21"),
		readyMember("act_three", "2001:db8::20"),
		readyMember("act_four", "203.0.113.22"),
		readyMember("act_five", "203.0.113.20"),
	})
	want := []BlockRefusal{"", BlockRefusedDuplicate, BlockRefusedDuplicate, "", BlockRefusedFull, BlockRefusedDuplicate}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("ReadyCapacity = %q, want %q", got, want)
	}
	if a.Full() {
		t.Fatal("a set with room is full")
	}
}

// A zero limit is the base engine's unlimited temporary set.
func TestBlockAdmissionReadyCapacityUnlimited(t *testing.T) {
	a := BlockAdmission{Temporary: 100000}
	var ready []BlockMember
	for i := range MaxBlockBatchMembers {
		ready = append(ready, readyMember(fmt.Sprintf("act_%d", i), fmt.Sprintf("203.0.113.%d", i)))
	}
	for i, r := range a.ReadyCapacity(ready) {
		if r != "" {
			t.Fatalf("member %d = %q without a limit", i, r)
		}
	}
	if a.Full() {
		t.Fatal("an unlimited set is full")
	}
}

// A set already at its limit is full before any member is asked about.
func TestBlockAdmissionFull(t *testing.T) {
	for _, tc := range []struct {
		temp, limit int
		full        bool
	}{{3, 3, true}, {4, 3, true}, {2, 3, false}, {0, 0, false}} {
		a := BlockAdmission{Temporary: tc.temp, Limit: tc.limit}
		if a.Full() != tc.full {
			t.Errorf("%d of %d: Full = %v", tc.temp, tc.limit, a.Full())
		}
		if got := a.ReadyCapacity([]BlockMember{readyMember("act_one", "203.0.113.20")}); (got[0] == BlockRefusedFull) != tc.full {
			t.Errorf("%d of %d: ready member = %q", tc.temp, tc.limit, got[0])
		}
	}
}

// An effect covers a request when it is permanent or ends no earlier than
// the request within the readback slack; the forecast judges its own
// blocks by the same rule.
func TestCoversExpiryAllowsTheReadbackSlack(t *testing.T) {
	wanted := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		held time.Time
		want bool
	}{
		{time.Time{}, true},
		{wanted.Add(time.Hour), true},
		{wanted, true},
		{wanted.Add(-blockReadbackSlack), true},
		{wanted.Add(-blockReadbackSlack - time.Nanosecond), false},
	} {
		if got := CoversExpiry(tc.held, wanted); got != tc.want {
			t.Errorf("held %v before the request: %v, want %v", wanted.Sub(tc.held), got, tc.want)
		}
	}
}
