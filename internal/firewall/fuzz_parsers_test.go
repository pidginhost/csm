//go:build linux

package firewall

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Whatever one member holds, it cannot change the answer for valid members
// around it.
func FuzzCheckBlockBatchIsolatesMembers(f *testing.F) {
	f.Add("act_x", "203.0.113.99", "reason", int64(time.Hour), uint8(0))
	f.Add("", "", "", int64(0), uint8(1))
	f.Add("act_v4", "::ffff:203.0.113.20", "\x00", int64(-1), uint8(0))
	f.Add("act_v4", "2001:db8::20", strings.Repeat("r", 300), int64(time.Microsecond), uint8(1))
	f.Add("act_y", "198.51.100.1", "\xff", int64(1<<62), uint8(0))
	f.Add("act_v4", "203.0.113.20", "reason", int64(time.Hour), uint8(0))
	f.Fuzz(func(t *testing.T, action, ip, reason string, ttl int64, at uint8) {
		fx := newBatchFixture(t, FirewallState{})
		v4, v6 := fx.member("act_v4", "203.0.113.20"), fx.member("act_v6", "2001:db8::20")
		odd := BlockMember{Action: action, IP: ip, Reason: reason, ExpiresAt: fx.at.Add(time.Duration(ttl))}
		members := []BlockMember{v4, v6}
		pos := int(at) % 3
		members = append(members[:pos], append([]BlockMember{odd}, members[pos:]...)...)
		got, err := fx.e.CheckBlockBatch(members)
		if err != nil {
			t.Fatal(err)
		}
		seenIP, seenAction := map[string]bool{}, map[string]bool{}
		for i, member := range members {
			isolated, err := fx.e.CheckBlockBatch([]BlockMember{member})
			if err != nil {
				t.Fatal(err)
			}
			want := isolated[0]
			if want == "" && (seenIP[member.IP] || seenAction[member.Action]) {
				want = BlockRefusedDuplicate
			}
			if got[i] != want {
				t.Fatalf("member %d refused %q, want isolated/collision answer %q next to %+v", i, got[i], want, odd)
			}
			if want == "" {
				seenIP[member.IP], seenAction[member.Action] = true, true
			}
		}
	})
}

// FuzzBlockBatchMembers feeds arbitrary member content around valid
// members: a member can only refuse itself, never poison the rest.
func FuzzBlockBatchMembers(f *testing.F) {
	f.Add("203.0.113.70", "member-x", "brute force", int64(time.Hour))
	f.Add("::ffff:203.0.113.71", "member x", "line\nbreak", int64(0))
	f.Add("2001:db8::70", "member-x", "", int64(time.Millisecond))
	f.Add("203.0.113.0/24", "batch-one", "brute force", int64(-time.Hour))
	f.Fuzz(func(t *testing.T, target, id, reason string, ttl int64) {
		e, s := batchPlanEngine(t, FirewallConfig{IPv6: true}, FirewallState{})
		odd := batchMember(id, target)
		odd.Reason, odd.TTL = reason, time.Duration(ttl)
		members := []ActionRequest{batchMember("member-first", "203.0.113.80"), odd, batchMember("member-last", "203.0.113.81")}
		result, err := e.BlockBatchRequest(batchHeader(), members, nil)
		if !errors.Is(err, errBatchPlanStop) || len(result.Refusals) != len(members) || result.Refusals[0] != "" || len(s.admitted) != 1 {
			t.Fatalf("batch = %q, %v, admitted %d", result.Refusals, err, len(s.admitted))
		}
		var ran []string
		for i, refusal := range result.Refusals {
			if refusal == "" {
				ran = append(ran, members[i].ID)
			}
		}
		plan := s.admitted[0]
		if len(plan.Members) != len(ran) || len(plan.After.Blocked) != len(ran) {
			t.Fatalf("planned %d members and %d rows for %v", len(plan.Members), len(plan.After.Blocked), ran)
		}
		for i, m := range plan.Members {
			if m.Request.ID != ran[i] || net.ParseIP(m.Request.Target) == nil || net.ParseIP(m.Request.Target).String() != m.Request.Target || m.Request.TTL <= 0 {
				t.Fatalf("planned member %d = %#v", i, m.Request)
			}
		}
	})
}
