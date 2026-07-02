//go:build linux

package firewall

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The kernel assigns a set-level default timeout to every element added
// without an explicit one, and the netlink library omits zero element
// timeouts entirely. A default timeout on the blocked sets therefore turns
// every permanent block (deny, promote) into a timed one that silently
// expires from the kernel while state.json still says blocked, with no
// periodic re-apply to converge. These tests pin the invariant: the blocked
// sets carry NO set-level default, permanent element adds carry NO element
// timeout, and temporary adds carry their intended element timeout.

func TestCreateSetsBlockedSetsHaveNoDefaultTimeout(t *testing.T) {
	conn, _ := nftConnCapturingRules(t)
	e := &Engine{
		conn: conn,
		cfg:  &FirewallConfig{IPv6: true},
	}
	e.table = conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
	if err := e.createSets(); err != nil {
		t.Fatalf("createSets: %v", err)
	}
	for _, tc := range []struct {
		name string
		set  *nftables.Set
	}{
		{"blocked_ips", e.setBlocked},
		{"blocked_ips6", e.setBlocked6},
	} {
		if tc.set == nil {
			t.Fatalf("%s not created", tc.name)
		}
		if !tc.set.HasTimeout {
			t.Errorf("%s HasTimeout = false, want true (temporary blocks need per-element timeouts)", tc.name)
		}
		if tc.set.Timeout != 0 {
			t.Errorf("%s set-level default timeout = %v, want 0 (kernel default expires permanent blocks)", tc.name, tc.set.Timeout)
		}
	}
}

// newBlockedSetWireTestEngine returns an engine wired to a capturing test
// conn with a blocked_ips set matching the production layout (per-element
// timeouts, no set default).
func newBlockedSetWireTestEngine(t *testing.T, conn *nftables.Conn) *Engine {
	t.Helper()
	table := conn.AddTable(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet})
	e := &Engine{
		conn:      conn,
		cfg:       &FirewallConfig{},
		statePath: t.TempDir(),
		table:     table,
	}
	e.setBlocked = &nftables.Set{
		Table: table, Name: "blocked_ips",
		KeyType: nftables.TypeIPAddr, HasTimeout: true,
	}
	return e
}

// newSetElemTimeouts extracts, from the captured netlink batch, the element
// timeouts of every NEWSETELEM message targeting setName. One slice entry
// per element; nil means the element carried no NFTA_SET_ELEM_TIMEOUT
// attribute (kernel semantics: never expires when the set has no default).
func newSetElemTimeouts(t *testing.T, msgs []netlink.Message, setName string) []*time.Duration {
	t.Helper()
	// Netlink attribute types carry flag bits (NLA_F_NESTED) in the high
	// bits; mask them off before comparing against NFTA_* constants.
	const nlaTypeMask = 0x3fff
	newElem := netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWSETELEM)
	var out []*time.Duration
	for _, m := range msgs {
		if m.Header.Type != newElem || len(m.Data) < 4 {
			continue
		}
		// Skip the 4-byte nfgenmsg header preceding the attributes.
		attrs, err := netlink.UnmarshalAttributes(m.Data[4:])
		if err != nil {
			t.Fatalf("unmarshal NEWSETELEM attributes: %v", err)
		}
		targetsSet := false
		var elemList []byte
		for _, a := range attrs {
			switch a.Type & nlaTypeMask {
			case unix.NFTA_SET_ELEM_LIST_SET:
				targetsSet = string(a.Data) == setName+"\x00"
			case unix.NFTA_SET_ELEM_LIST_ELEMENTS:
				elemList = a.Data
			}
		}
		if !targetsSet || elemList == nil {
			continue
		}
		items, err := netlink.UnmarshalAttributes(elemList)
		if err != nil {
			t.Fatalf("unmarshal element list: %v", err)
		}
		for _, item := range items {
			sub, err := netlink.UnmarshalAttributes(item.Data)
			if err != nil {
				t.Fatalf("unmarshal element attributes: %v", err)
			}
			var timeout *time.Duration
			for _, sa := range sub {
				if sa.Type&nlaTypeMask == unix.NFTA_SET_ELEM_TIMEOUT {
					d := time.Duration(binary.BigEndian.Uint64(sa.Data)) * time.Millisecond
					timeout = &d
				}
			}
			out = append(out, timeout)
		}
	}
	return out
}

func TestTemporaryBlockCarriesElementTimeout(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)

	if err := e.BlockIPForce("192.0.2.10", "temp block", time.Hour); err != nil {
		t.Fatalf("BlockIPForce: %v", err)
	}

	timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
	if len(timeouts) != 1 {
		t.Fatalf("blocked_ips element adds = %d, want 1", len(timeouts))
	}
	if timeouts[0] == nil {
		t.Fatal("temporary block element carries no kernel timeout; it would never expire")
	}
	if *timeouts[0] != time.Hour {
		t.Fatalf("temporary block element timeout = %v, want %v", *timeouts[0], time.Hour)
	}
}

func TestPermanentBlockCarriesNoElementTimeout(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)

	if err := e.BlockIPForce("192.0.2.11", "operator deny", 0); err != nil {
		t.Fatalf("BlockIPForce: %v", err)
	}

	timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
	if len(timeouts) != 1 {
		t.Fatalf("blocked_ips element adds = %d, want 1", len(timeouts))
	}
	if timeouts[0] != nil {
		t.Fatalf("permanent block element carries kernel timeout %v; it must never expire", *timeouts[0])
	}
}

func TestPromoteToPermanentBlockReAddsWithoutTimeout(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	writeRawFirewallState(t, e, FirewallState{
		Blocked: []BlockedEntry{{
			IP:        "192.0.2.12",
			Reason:    "temp block",
			BlockedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}},
	})

	if err := e.PromoteToPermanentBlock("192.0.2.12", "escalated"); err != nil {
		t.Fatalf("PromoteToPermanentBlock: %v", err)
	}

	timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
	if len(timeouts) != 1 {
		t.Fatalf("blocked_ips element adds = %d, want 1 (the timeout-free re-add)", len(timeouts))
	}
	if timeouts[0] != nil {
		t.Fatalf("promoted block element carries kernel timeout %v; it must never expire", *timeouts[0])
	}

	state := readRawFirewallState(t, e)
	if len(state.Blocked) != 1 {
		t.Fatalf("blocked entries = %d, want 1", len(state.Blocked))
	}
	if !state.Blocked[0].ExpiresAt.IsZero() {
		t.Fatalf("promoted entry ExpiresAt = %v, want zero (permanent)", state.Blocked[0].ExpiresAt)
	}
}
