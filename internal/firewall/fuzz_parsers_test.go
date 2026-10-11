//go:build linux

package firewall

import (
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
