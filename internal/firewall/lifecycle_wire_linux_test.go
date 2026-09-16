//go:build linux

package firewall

import (
	"testing"
	"time"
)

func TestLifecycleWireNeverEncodesTemporaryAsPermanent(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	now := time.Now()
	entries := actionElements([]ActionElement{{Key: []byte{192, 0, 2, 151}, ExpiresAt: now.Add(500 * time.Microsecond), Comment: "identity"}}, now)
	if err := conn.SetAddElements(e.setBlocked, entries); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
	for _, ttl := range timeouts {
		if ttl == nil || *ttl <= 0 {
			t.Fatal("temporary action encoded as permanent")
		}
	}
}
func TestLifecycleWireRetainsAbsoluteExpiry(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	expiry := time.Now().Add(time.Hour)
	action := FirewallAction{KernelAfter: []ActionSet{{Exists: true, Name: e.setBlocked.Name, Elements: []ActionElement{{Key: []byte{192, 0, 2, 152}, ExpiresAt: expiry, Comment: "identity"}}}}}
	if err := (engineActionKernel{e}).ApplyFirewallAction(action); err != nil {
		t.Fatal(err)
	}
	timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
	if len(timeouts) != 1 || timeouts[0] == nil || *timeouts[0] > time.Hour || *timeouts[0] < time.Hour-time.Second {
		t.Fatalf("timeout changed: %#v", timeouts)
	}
}
