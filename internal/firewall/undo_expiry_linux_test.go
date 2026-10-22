//go:build linux

package firewall

import (
	"reflect"
	"testing"
	"time"
)

// A lease ahead of wall time must not put expired rows into the snapshot
// while kernel planning correctly omits them from its desired sets.
func TestPrepareFirewallUndoUsesLeaseClock(t *testing.T) {
	wall := time.Now().Round(0)
	lease := wall.Add(2 * time.Hour)
	e := newBlockedSetWireTestEngine(t, leaseActionReadConn(t, nil))
	e.expiryClock = func() time.Time { return wall }
	e.leaseClock = func() (time.Time, time.Time) { return lease, lease }
	want := FirewallState{
		Blocked:     []BlockedEntry{{IP: "203.0.113.82", ExpiresAt: lease.Add(time.Hour), Unverified: true}, {IP: "203.0.113.83"}},
		Allowed:     []AllowedEntry{{IP: "192.0.2.81", ExpiresAt: lease.Add(time.Hour)}, {IP: "192.0.2.82"}},
		BlockedNet:  []SubnetEntry{{CIDR: "198.51.100.16/28", ExpiresAt: lease.Add(time.Hour)}, {CIDR: "198.51.100.32/28"}},
		PortAllowed: []PortAllowEntry{{IP: "192.0.2.83", Port: 443, Proto: "tcp"}},
	}
	plan := FirewallAction{Request: ActionRequest{Operation: "undo"}, After: FirewallState{
		Blocked:     append([]BlockedEntry{{IP: "203.0.113.80", ExpiresAt: wall.Add(time.Hour)}, {IP: "203.0.113.81", ExpiresAt: lease, Unverified: true}}, want.Blocked...),
		Allowed:     append([]AllowedEntry{{IP: "192.0.2.80", ExpiresAt: wall.Add(time.Hour)}}, want.Allowed...),
		BlockedNet:  append([]SubnetEntry{{CIDR: "198.51.100.0/28", ExpiresAt: wall.Add(time.Hour)}}, want.BlockedNet...),
		PortAllowed: want.PortAllowed,
	}}
	if err := (engineActionKernel{e}).PrepareFirewallUndo(&plan); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.After, want) || !plan.CreatedAt.Equal(lease) {
		t.Fatalf("undo planned beyond lease expiry: %#v at %v", plan.After, plan.CreatedAt)
	}
}
