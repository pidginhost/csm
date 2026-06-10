//go:build linux

package firewall

import (
	"io"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
)

// Test state-management wrappers on Engine methods.
// These exercise the state JSON I/O paths without needing real nftables.
// The actual nftables operations fail/panic — we catch that.

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	return &Engine{
		statePath: dir,
		cfg:       &FirewallConfig{Enabled: true},
	}
}

func namedIPv4Set(name string) *nftables.Set {
	set := anonymousIPv4Set(name)
	set.Anonymous = false
	return set
}

func nftConnReturningErr(t *testing.T, errno syscall.Errno) *nftables.Conn {
	t.Helper()
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		return nltest.Error(int(errno), req)
	}))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func nftConnReturningErrsThenOK(t *testing.T, errnos ...syscall.Errno) (*nftables.Conn, func() int) {
	t.Helper()
	sends := 0
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		defer func() { sends++ }()
		if sends < len(errnos) {
			return nltest.Error(int(errnos[sends]), req)
		}
		acks := make([]netlink.Message, 0, len(req))
		for _, msg := range req {
			if msg.Header.Flags&netlink.Acknowledge == 0 {
				continue
			}
			acks = append(acks, netlink.Message{
				Header: netlink.Header{
					Length:   4,
					Type:     netlink.Error,
					Sequence: msg.Header.Sequence,
					PID:      msg.Header.PID,
				},
				Data: []byte{0, 0, 0, 0},
			})
		}
		return acks, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return conn, func() int { return sends }
}

func TestEngineBlockIPStateOnly(t *testing.T) {
	e := newTestEngine(t)

	// BlockIP will panic on nil conn — just test saveBlockedEntry directly
	_ = e.saveBlockedEntry(BlockedEntry{
		IP:        "203.0.113.5",
		Reason:    "brute-force",
		BlockedAt: time.Now(),
	})

	state := e.loadStateFile()
	if len(state.Blocked) != 1 {
		t.Errorf("blocked = %d, want 1", len(state.Blocked))
	}
	if state.Blocked[0].IP != "203.0.113.5" {
		t.Errorf("IP = %q", state.Blocked[0].IP)
	}
}

func TestEngineAllowIPStateOnly(t *testing.T) {
	e := newTestEngine(t)

	e.saveAllowedEntry(AllowedEntry{
		IP:     "10.0.0.1",
		Reason: "admin access",
	})

	state := e.loadStateFile()
	if len(state.Allowed) != 1 {
		t.Errorf("allowed = %d, want 1", len(state.Allowed))
	}
}

func TestEngineBlockSubnetStateOnly(t *testing.T) {
	e := newTestEngine(t)

	e.saveSubnetEntry(SubnetEntry{
		CIDR:      "192.168.0.0/16",
		Reason:    "test block",
		BlockedAt: time.Now(),
	})

	state := e.loadStateFile()
	if len(state.BlockedNet) != 1 {
		t.Errorf("blocked_net = %d, want 1", len(state.BlockedNet))
	}
}

func TestEngineBlockSubnetRejectsSaturatedCIDRBeforeNetlink(t *testing.T) {
	e := newTestEngine(t)
	e.setBlockedNet = &nftables.Set{Name: "blocked_nets"}

	err := e.BlockSubnet("255.255.255.255/32", "bad range", 0)
	if err == nil || !strings.Contains(err.Error(), "no safe interval end") {
		t.Fatalf("BlockSubnet saturated CIDR error = %v, want safe interval error", err)
	}

	state := e.loadStateFile()
	if len(state.BlockedNet) != 0 {
		t.Fatalf("saturated CIDR persisted state: %+v", state.BlockedNet)
	}
}

// BlockSubnet persists state before the kernel add (state seeds the next
// Apply); on a kernel failure the un-applied row must be rolled back so
// state never advertises a block the kernel does not enforce.
func TestBlockSubnetRollsBackStateOnKernelQueueFailure(t *testing.T) {
	e := newTestEngine(t)
	e.conn = &nftables.Conn{}
	e.setBlockedNet = anonymousIPv4Set("blocked_nets")

	err := e.BlockSubnet("198.51.100.0/24", "spray", time.Hour)
	if err == nil {
		t.Fatal("BlockSubnet must fail when the kernel add cannot be queued")
	}
	if !strings.Contains(err.Error(), "anonymous sets cannot be updated") {
		t.Fatalf("BlockSubnet error = %v, want anonymous-set update error", err)
	}
	state := e.loadStateFile()
	if len(state.BlockedNet) != 0 {
		t.Fatalf("state kept un-applied subnet block after kernel failure: %+v", state.BlockedNet)
	}
}

// UnblockIP removes the state row before the kernel delete; a kernel failure
// must restore it so the operator still sees the block and can retry.
func TestUnblockIPRestoresStateOnKernelQueueFailure(t *testing.T) {
	e := newTestEngine(t)
	e.conn = &nftables.Conn{}
	e.setBlocked = anonymousIPv4Set("blocked_ips")
	if err := e.saveBlockedEntry(BlockedEntry{
		IP:        "203.0.113.9",
		Reason:    "test",
		BlockedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	err := e.UnblockIP("203.0.113.9")
	if err == nil {
		t.Fatal("UnblockIP must fail when the kernel delete cannot be queued")
	}
	if !strings.Contains(err.Error(), "anonymous sets cannot be updated") {
		t.Fatalf("UnblockIP error = %v, want anonymous-set update error", err)
	}
	state := e.loadStateFile()
	if len(state.Blocked) != 1 || state.Blocked[0].IP != "203.0.113.9" {
		t.Fatalf("blocked entry must be restored after failed kernel delete: %+v", state.Blocked)
	}
}

func TestUnblockIPDropsStateWhenKernelElementAlreadyMissing(t *testing.T) {
	e := newTestEngine(t)
	e.conn = nftConnReturningErr(t, syscall.ENOENT)
	e.setBlocked = namedIPv4Set("blocked_ips")
	if err := e.saveBlockedEntry(BlockedEntry{
		IP:        "203.0.113.10",
		Reason:    "test",
		BlockedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	if err := e.UnblockIP("203.0.113.10"); err != nil {
		t.Fatalf("UnblockIP should treat missing kernel element as success: %v", err)
	}
	state := e.loadStateFile()
	if len(state.Blocked) != 0 {
		t.Fatalf("blocked entry survived missing-element unblock: %+v", state.Blocked)
	}
}

func TestAllowMethodsRestoreStateOnAllowedAddQueueFailure(t *testing.T) {
	tests := []struct {
		name string
		call func(*Engine) error
	}{
		{
			name: "AllowIP",
			call: func(e *Engine) error {
				return e.AllowIP("10.0.0.45", "manual")
			},
		},
		{
			name: "TempAllowIP",
			call: func(e *Engine) error {
				return e.TempAllowIP("10.0.0.45", "manual", time.Minute)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t)
			e.conn = &nftables.Conn{}
			e.setAllowed = anonymousIPv4Set("allowed_ips")
			if err := e.saveBlockedEntry(BlockedEntry{
				IP:        "10.0.0.45",
				Reason:    "test block",
				BlockedAt: time.Now(),
			}); err != nil {
				t.Fatal(err)
			}

			err := tc.call(e)
			if err == nil || !strings.Contains(err.Error(), "adding to allowed set") {
				t.Fatalf("%s error = %v, want allowed-add error", tc.name, err)
			}
			if !strings.Contains(err.Error(), "anonymous sets cannot be updated") {
				t.Fatalf("%s error = %v, want anonymous-set update error", tc.name, err)
			}
			state := e.loadStateFile()
			if len(state.Blocked) != 1 || state.Blocked[0].IP != "10.0.0.45" {
				t.Fatalf("blocked entry must be restored after failed %s: %+v", tc.name, state.Blocked)
			}
			if len(state.Allowed) != 0 {
				t.Fatalf("allowed entry survived failed %s: %+v", tc.name, state.Allowed)
			}
		})
	}
}

func TestAllowMethodsRetryStaleBlockedKernelElement(t *testing.T) {
	tests := []struct {
		name string
		call func(*Engine) error
	}{
		{
			name: "AllowIP",
			call: func(e *Engine) error {
				return e.AllowIP("10.0.0.46", "manual")
			},
		},
		{
			name: "TempAllowIP",
			call: func(e *Engine) error {
				return e.TempAllowIP("10.0.0.46", "manual", time.Minute)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t)
			conn, sends := nftConnReturningErrsThenOK(t, syscall.ENOENT, syscall.ENOENT)
			e.conn = conn
			e.setBlocked = namedIPv4Set("blocked_ips")
			e.setAllowed = namedIPv4Set("allowed_ips")
			if err := e.saveBlockedEntry(BlockedEntry{
				IP:        "10.0.0.46",
				Reason:    "stale block",
				BlockedAt: time.Now(),
			}); err != nil {
				t.Fatal(err)
			}

			if err := tc.call(e); err != nil {
				t.Fatalf("%s should retry stale blocked kernel element: %v", tc.name, err)
			}
			if sends() != 3 {
				t.Fatalf("%s netlink sends = %d, want initial batch, delete retry, add retry", tc.name, sends())
			}
			state := e.loadStateFile()
			if len(state.Blocked) != 0 {
				t.Fatalf("blocked entry survived stale-kernel %s: %+v", tc.name, state.Blocked)
			}
			if len(state.Allowed) != 1 || state.Allowed[0].IP != "10.0.0.46" {
				t.Fatalf("allowed entry missing after stale-kernel %s: %+v", tc.name, state.Allowed)
			}
			if tc.name == "TempAllowIP" && state.Allowed[0].ExpiresAt.IsZero() {
				t.Fatalf("temporary allow missing expiry after retry: %+v", state.Allowed[0])
			}
		})
	}
}

func TestEngineIsSubnetBlockedUsesCanonicalCIDR(t *testing.T) {
	e := newTestEngine(t)

	e.saveSubnetEntry(SubnetEntry{
		CIDR:      "198.51.100.0/24",
		Reason:    "test block",
		BlockedAt: time.Now(),
	})

	if !e.IsSubnetBlocked("198.51.100.99/24") {
		t.Fatal("expected canonical /24 subnet to be blocked")
	}
	if e.IsSubnetBlocked("198.51.101.0/24") {
		t.Fatal("unexpected blocked status for neighboring subnet")
	}
}

func TestEngineSaveSubnetEntryDeduplicates(t *testing.T) {
	e := newTestEngine(t)

	e.saveSubnetEntry(SubnetEntry{CIDR: "203.0.113.0/24", Reason: "first", BlockedAt: time.Now()})
	e.saveSubnetEntry(SubnetEntry{CIDR: "203.0.113.0/24", Reason: "second", BlockedAt: time.Now()})

	state := e.loadStateFile()
	if len(state.BlockedNet) != 1 {
		t.Fatalf("blocked_net = %d, want 1", len(state.BlockedNet))
	}
	if state.BlockedNet[0].Reason != "first" {
		t.Fatalf("duplicate subnet overwrote state: %+v", state.BlockedNet[0])
	}
}

func TestEngineRemoveAllowedBySourceStateOnly(t *testing.T) {
	e := newTestEngine(t)

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "admin", Source: "manual"})
	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "auto", Source: "dyndns"})

	// Remove only the dyndns source
	removed := e.removeAllowedStateBySource("10.0.0.1", "dyndns")
	if removed {
		t.Error("IP still has manual entry, should not be fully removed")
	}

	state := e.loadStateFile()
	if len(state.Allowed) != 1 {
		t.Errorf("allowed = %d, want 1", len(state.Allowed))
	}
	if state.Allowed[0].Source != "manual" {
		t.Errorf("remaining source = %q, want manual", state.Allowed[0].Source)
	}
}

func TestEngineRemoveAllowedBySourceFullRemoval(t *testing.T) {
	e := newTestEngine(t)

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "test", Source: "dyndns"})

	removed := e.removeAllowedStateBySource("10.0.0.1", "dyndns")
	if !removed {
		t.Error("only entry removed, should be fully removed")
	}
}

func TestEngineRemoveAllowedBySourceNotFound(t *testing.T) {
	e := newTestEngine(t)

	removed := e.removeAllowedStateBySource("10.0.0.1", "dyndns")
	if removed {
		t.Error("nothing to remove, should return false")
	}
}

func TestEngineIsBlockedNoConn(t *testing.T) {
	e := newTestEngine(t)
	// Without nftables conn, IsBlocked just returns false
	if e.IsBlocked("203.0.113.5") {
		t.Error("no conn should return false")
	}
}

func TestEngineCleanExpiredAllowsNoExpired(t *testing.T) {
	e := newTestEngine(t)
	// Nothing to clean
	cleaned := e.CleanExpiredAllows()
	if cleaned != 0 {
		t.Errorf("cleaned = %d, want 0", cleaned)
	}
}

func TestEngineCleanExpiredSubnetsNoExpired(t *testing.T) {
	e := newTestEngine(t)
	cleaned := e.CleanExpiredSubnets()
	if cleaned != 0 {
		t.Errorf("cleaned = %d, want 0", cleaned)
	}
}
