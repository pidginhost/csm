//go:build linux

package firewall

import (
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// delSetElemCount counts the DELSETELEM messages in the captured batch that
// target setName.
func delSetElemCount(t *testing.T, msgs []netlink.Message, setName string) int {
	t.Helper()
	const nlaTypeMask = 0x3fff
	delElem := netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_DELSETELEM)
	n := 0
	for _, m := range msgs {
		if m.Header.Type != delElem || len(m.Data) < 4 {
			continue
		}
		attrs, err := netlink.UnmarshalAttributes(m.Data[4:])
		if err != nil {
			t.Fatalf("unmarshal DELSETELEM attributes: %v", err)
		}
		for _, a := range attrs {
			if a.Type&nlaTypeMask == unix.NFTA_SET_ELEM_LIST_SET && string(a.Data) == setName+"\x00" {
				n++
			}
		}
	}
	return n
}

// nf_tables treats NEWSETELEM without NLM_F_EXCL on an existing key as an
// acknowledged no-op: the element keeps its old timeout. An operator deny on
// an auto-blocked address therefore left the kernel expiring the block after
// the original hour while state.json, the UI and `csm firewall status` all
// said permanent. The forced path must replace the element, as promotion does.
func TestBlockIPForceReplacesExistingElementTimeout(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	writeRawFirewallState(t, e, FirewallState{
		Blocked: []BlockedEntry{{
			IP:        "192.0.2.13",
			Reason:    "auto-block",
			BlockedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}},
	})

	if err := e.BlockIPForce("192.0.2.13", "operator deny", 0); err != nil {
		t.Fatalf("BlockIPForce: %v", err)
	}

	if got := delSetElemCount(t, *captured, "blocked_ips"); got != 1 {
		t.Fatalf("blocked_ips element deletes = %d, want 1 (the timed element must go before the permanent re-add)", got)
	}
	timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
	if len(timeouts) != 1 || timeouts[0] != nil {
		t.Fatalf("blocked_ips element adds = %v, want exactly one add with no timeout", timeouts)
	}
	state := readRawFirewallState(t, e)
	if len(state.Blocked) != 1 || !state.Blocked[0].ExpiresAt.IsZero() {
		t.Fatalf("state after deny = %+v, want one permanent entry", state.Blocked)
	}
}

// The inverse drift: a temporary ban laid over a permanent block must expire
// in the kernel when state.json says it does, or the address stays dropped
// forever while every CSM surface reports it unblocked.
func TestBlockIPForceTempBanOverPermanentReplacesElement(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	writeRawFirewallState(t, e, FirewallState{
		Blocked: []BlockedEntry{{
			IP:        "192.0.2.14",
			Reason:    "operator deny",
			BlockedAt: time.Now(),
		}},
	})

	if err := e.BlockIPForce("192.0.2.14", "tempban", 24*time.Hour); err != nil {
		t.Fatalf("BlockIPForce: %v", err)
	}

	if got := delSetElemCount(t, *captured, "blocked_ips"); got != 1 {
		t.Fatalf("blocked_ips element deletes = %d, want 1", got)
	}
	timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
	if len(timeouts) != 1 || timeouts[0] == nil || *timeouts[0] != 24*time.Hour {
		t.Fatalf("blocked_ips element adds = %v, want one add carrying the 24h timeout", timeouts)
	}
}

// A first-time block has nothing to replace; it must stay a plain add so a
// missing element never turns the batch into an ENOENT failure.
func TestBlockIPForceNewAddressDoesNotDelete(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)

	if err := e.BlockIPForce("192.0.2.15", "operator deny", 0); err != nil {
		t.Fatalf("BlockIPForce: %v", err)
	}
	if got := delSetElemCount(t, *captured, "blocked_ips"); got != 0 {
		t.Fatalf("blocked_ips element deletes = %d, want 0 for a new address", got)
	}
}
