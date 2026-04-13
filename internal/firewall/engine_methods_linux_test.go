//go:build linux

package firewall

import (
	"testing"
	"time"
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

func TestEngineBlockIPStateOnly(t *testing.T) {
	e := newTestEngine(t)

	// BlockIP will panic on nil conn — just test saveBlockedEntry directly
	e.saveBlockedEntry(BlockedEntry{
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
