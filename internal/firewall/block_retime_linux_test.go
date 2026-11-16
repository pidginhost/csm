//go:build linux

package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// setChanges lists, in order, what the captured batch does to the elements
// of setName: "flush" for a deletion that names no element, "delete" for
// one that does, and "add".
func setChanges(t *testing.T, msgs []netlink.Message, setName string) []string {
	t.Helper()
	const nlaTypeMask = 0x3fff
	kinds := map[netlink.HeaderType]string{
		netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWSETELEM): "add",
		netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_DELSETELEM): "delete",
	}
	var out []string
	for _, m := range msgs {
		kind, ok := kinds[m.Header.Type]
		if !ok || len(m.Data) < 4 {
			continue
		}
		attrs, err := netlink.UnmarshalAttributes(m.Data[4:])
		if err != nil {
			t.Fatalf("unmarshal set element attributes: %v", err)
		}
		targets, elements := false, false
		for _, a := range attrs {
			switch a.Type & nlaTypeMask {
			case unix.NFTA_SET_ELEM_LIST_SET:
				targets = string(a.Data) == setName+"\x00"
			case unix.NFTA_SET_ELEM_LIST_ELEMENTS:
				elements = len(a.Data) > 0
			}
		}
		if !targets {
			continue
		}
		if kind == "delete" && !elements {
			kind = "flush"
		}
		out = append(out, kind)
	}
	return out
}

// retimeEngine is a wire engine over rows that last an hour, forever, are
// held back as unverified, have expired, and name an IPv6 address.
func retimeEngine(t *testing.T, conn *nftables.Conn) *Engine {
	t.Helper()
	e := newBlockedSetWireTestEngine(t, conn)
	at := e.expiryNow()
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{
		{IP: "192.0.2.80", ExpiresAt: at.Add(time.Hour), ActionID: "act_timed"},
		{IP: "192.0.2.81"},
		{IP: "192.0.2.82", ExpiresAt: at.Add(2 * time.Hour), ActionID: "act_held", Unverified: true},
		{IP: "192.0.2.83", ExpiresAt: at.Add(-time.Minute)},
		{IP: "2001:db8::80", ExpiresAt: at.Add(30 * time.Minute)},
	}})
	return e
}

func retimedTimeouts(t *testing.T, msgs []netlink.Message, setName string) []time.Duration {
	t.Helper()
	var out []time.Duration
	for _, timeout := range newSetElemTimeouts(t, msgs, setName) {
		if timeout == nil {
			out = append(out, 0)
		} else {
			out = append(out, *timeout)
		}
	}
	return out
}

// Retiming replaces each blocked set in one transaction: the set is
// emptied and filled from the saved rows, a timed block with the time its
// row has left. Rows that are held back or expired get no element.
func TestRetimeBlocksReplacesEachSetFromItsRows(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := retimeEngine(t, conn)
	e.cfg.IPv6 = true
	e.setBlocked6 = &nftables.Set{Table: e.table, Name: "blocked_ips6", KeyType: nftables.TypeIP6Addr, HasTimeout: true}
	if err := e.RetimeBlocks(); err != nil {
		t.Fatal(err)
	}
	for set, want := range map[string][]time.Duration{
		"blocked_ips":  {time.Hour, 0},
		"blocked_ips6": {30 * time.Minute},
	} {
		if got := setChanges(t, *captured, set); !slices.Equal(got, []string{"flush", "add"}) {
			t.Errorf("%s changes = %v; want it emptied, then filled", set, got)
		}
		if got := retimedTimeouts(t, *captured, set); !slices.Equal(got, want) {
			t.Errorf("%s element timeouts = %v, want %v", set, got, want)
		}
	}
}

// A family the firewall does not filter is left alone, also when an
// earlier ruleset left its set behind in the engine. A set with no row
// left is still emptied.
func TestRetimeBlocksLeavesAnUnfilteredFamilyAlone(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := retimeEngine(t, conn)
	e.setBlocked6 = &nftables.Set{Table: e.table, Name: "blocked_ips6", KeyType: nftables.TypeIP6Addr, HasTimeout: true}
	if err := e.RetimeBlocks(); err != nil {
		t.Fatal(err)
	}
	if got := setChanges(t, *captured, "blocked_ips6"); len(got) != 0 {
		t.Errorf("blocked_ips6 changes = %v; want none while IPv6 is not filtered", got)
	}
	if got := setChanges(t, *captured, "blocked_ips"); !slices.Equal(got, []string{"flush", "add"}) {
		t.Errorf("blocked_ips changes = %v; want it emptied, then filled", got)
	}

	conn, captured = nftConnCapturingRules(t)
	e = newBlockedSetWireTestEngine(t, conn)
	if err := e.RetimeBlocks(); err != nil {
		t.Fatal(err)
	}
	if got := setChanges(t, *captured, "blocked_ips"); !slices.Equal(got, []string{"flush"}) {
		t.Errorf("blocked_ips changes without rows = %v; want it emptied", got)
	}
}

// Nothing is emptied when the rows cannot be trusted or the kernel refuses
// the transaction: the error reaches the caller and the sets stay as they
// were.
func TestRetimeBlocksRefusesWithoutSendingOnUnreadableRows(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	if err := os.WriteFile(filepath.Join(e.statePath, "state.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.renameStateAside = func(string, string) error { return errors.New("fixture rename failure") }
	if err := e.RetimeBlocks(); !errors.Is(err, ErrStateNotKeptAside) {
		t.Errorf("unreadable rows: error %v, want the state fault", err)
	}
	if got := setChanges(t, *captured, "blocked_ips"); len(got) != 0 {
		t.Errorf("unreadable rows: blocked_ips changes = %v; want none", got)
	}

	refusing, _ := nftConnReturningErrsThenOK(t, syscall.ENOENT)
	e = retimeEngine(t, refusing)
	if err := e.RetimeBlocks(); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("refused transaction: error %v, want the kernel's", err)
	}

	conn, _ = nftConnCapturingRules(t)
	e = retimeEngine(t, conn)
	e.conn = nil
	if err := e.RetimeBlocks(); err == nil {
		t.Error("an engine without a connection reported its blocks retimed")
	}
}

// Retiming must not turn a read failure into an empty or stale policy.
func TestRetimeBlocksRejectsEveryUnreadableImage(t *testing.T) {
	for _, mode := range []string{"kept aside", "cached", "already kept aside", "read error"} {
		t.Run(mode, func(t *testing.T) {
			conn, captured := nftConnCapturingRules(t)
			e := retimeEngine(t, conn)
			if mode == "cached" {
				e.mu.Lock()
				e.loadStateFile()
				e.mu.Unlock()
			}
			path := filepath.Join(e.statePath, "state.json")
			if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
			if mode == "already kept aside" {
				e.mu.Lock()
				e.loadStateFile()
				e.mu.Unlock()
				if e.stateSetAside == "" {
					t.Fatal("fixture did not preserve the corrupt state")
				}
			}
			if mode == "read error" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := e.RetimeBlocks(); err == nil {
				t.Error("unreadable image reported success")
			}
			if err := e.conn.Flush(); err != nil {
				t.Fatal(err)
			}
			if got := setChanges(t, *captured, "blocked_ips"); len(got) != 0 {
				t.Errorf("unreadable image sent changes: %v", got)
			}
		})
	}
}

// The durable owner must be bypassed before any state or kernel operation.
func TestRetimeBlocksLeavesDurableOwnershipAlone(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := retimeEngine(t, conn)
	e.lifecycle = &Lifecycle{}
	if err := e.RetimeBlocks(); err != nil {
		t.Fatal(err)
	}
	if got := setChanges(t, *captured, "blocked_ips"); len(got) != 0 {
		t.Fatalf("durable retiming sent changes: %v", got)
	}
}

// A transaction the engine cannot finish queueing is dropped whole: the
// emptying it began with must never ride along with a later change.
func TestRetimeBlocksDropsATransactionItCannotFinish(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := retimeEngine(t, conn)
	e.setBlocked.Anonymous = true
	if err := e.RetimeBlocks(); err == nil {
		t.Fatal("a set that takes no elements reported its blocks retimed")
	}
	if err := e.conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := setChanges(t, *captured, "blocked_ips"); len(got) != 0 {
		t.Fatalf("blocked_ips changes sent by a later flush = %v; want none", got)
	}
}
