//go:build linux

package firewall

import (
	"net"
	"testing"
	"time"

	"github.com/google/nftables"
)

func TestLeaseUndoRetryUsesRemainingTime(t *testing.T) {
	for _, expired := range []bool{false, true} {
		conn, captured := nftConnCapturingRules(t)
		e := newBlockedSetWireTestEngine(t, conn)
		at := time.Now().Round(0)
		clock := &leaseSteps{wall: at, elapsed: at}
		e.leaseClock = clock.read
		leaseNow(e)
		clock.advance(time.Minute)
		clock.step(-time.Hour)
		expires := at.Add(time.Hour)
		if expired {
			expires = at.Add(time.Minute)
		}
		elem := []nftables.SetElement{{Key: net.ParseIP("192.0.2.113").To4(), Timeout: time.Hour}}
		e.mu.Lock()
		err := e.retryBlockAddAfterMissingElement(e.setBlocked, elem, nil, nil, false, expires)
		e.mu.Unlock()
		if expired {
			if err == nil || len(*captured) != 0 {
				t.Fatalf("expired retry sent a batch: %v, %v", err, *captured)
			}
			continue
		}
		timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
		if err != nil || len(timeouts) != 1 || timeouts[0] == nil || *timeouts[0] != 59*time.Minute {
			t.Fatalf("retry renewed the undo lease: %v, %v", timeouts, err)
		}
	}
}
