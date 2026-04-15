//go:build linux

package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Additional tests that push engine.go helpers without requiring a real
// nftables conn. These complement engine_methods_linux_test.go,
// engine_state_linux_test.go, engine_coverage_linux_test.go, and
// engine_deeper_linux_test.go.

// --- RemoveAllowIPPort ---------------------------------------------------

func TestEngineRemoveAllowIPPortEmptyState(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	if err := e.RemoveAllowIPPort("10.0.0.1", 22, "tcp"); err == nil {
		t.Error("expected error for missing entry in empty state")
	}
}

func TestEngineRemoveAllowIPPortPreservesOthers(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	_ = e.AllowIPPort("10.0.0.5", 22, "tcp", "ssh")
	_ = e.AllowIPPort("10.0.0.5", 443, "tcp", "https")
	_ = e.AllowIPPort("10.0.0.6", 22, "tcp", "ssh2")

	if err := e.RemoveAllowIPPort("10.0.0.5", 22, "tcp"); err != nil {
		t.Fatalf("RemoveAllowIPPort: %v", err)
	}

	st := e.loadStateFile()
	if len(st.PortAllowed) != 2 {
		t.Fatalf("remaining PortAllowed = %d, want 2", len(st.PortAllowed))
	}
	for _, p := range st.PortAllowed {
		if p.IP == "10.0.0.5" && p.Port == 22 {
			t.Errorf("removed entry still present: %+v", p)
		}
	}
}

// --- AllowIPPort validation ----------------------------------------------

func TestEngineAllowIPPortInvalidProtocolCoercedToTCP(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	if err := e.AllowIPPort("10.0.0.5", 22, "sctp", "weird"); err != nil {
		t.Fatalf("AllowIPPort: %v", err)
	}
	st := e.loadStateFile()
	if len(st.PortAllowed) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(st.PortAllowed))
	}
	if st.PortAllowed[0].Proto != "tcp" {
		t.Errorf("unknown proto should be coerced to tcp, got %q", st.PortAllowed[0].Proto)
	}
}

// --- saveState atomic semantics ------------------------------------------

func TestEngineSaveStateOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	// First write
	e.saveState(&FirewallState{
		Blocked: []BlockedEntry{{IP: "1.1.1.1", BlockedAt: time.Now()}},
	})
	// Second write with different content
	e.saveState(&FirewallState{
		Blocked: []BlockedEntry{{IP: "2.2.2.2", BlockedAt: time.Now()}},
	})

	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var loaded FirewallState
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(loaded.Blocked) != 1 || loaded.Blocked[0].IP != "2.2.2.2" {
		t.Errorf("second save should overwrite, got %+v", loaded.Blocked)
	}
}

// --- loadStateFile round-trip with PortAllowed ---------------------------

func TestEngineLoadStateFilePreservesPortAllowedList(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	_ = e.AllowIPPort("10.0.0.1", 22, "tcp", "ssh")
	_ = e.AllowIPPort("10.0.0.1", 53, "udp", "dns")

	st := e.loadStateFile()
	if len(st.PortAllowed) != 2 {
		t.Fatalf("PortAllowed = %d, want 2", len(st.PortAllowed))
	}
}

// --- saveBlockedEntry explicit Source -----------------------------------

func TestEngineSaveBlockedEntryExplicitSourcePreserved(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveBlockedEntry(BlockedEntry{
		IP:        "203.0.113.9",
		Reason:    "manual block",
		Source:    "cli",
		BlockedAt: time.Now(),
	})
	st := e.loadStateFile()
	if len(st.Blocked) != 1 {
		t.Fatalf("Blocked = %d", len(st.Blocked))
	}
	if st.Blocked[0].Source != "cli" {
		t.Errorf("Source = %q, want cli (should not be overwritten)", st.Blocked[0].Source)
	}
}

// --- removeBlockedState when file missing --------------------------------

func TestEngineRemoveBlockedStateEmptyFile(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	// no-op on empty state
	e.removeBlockedState("203.0.113.5")
	st := e.loadStateFile()
	if len(st.Blocked) != 0 {
		t.Errorf("Blocked should remain empty, got %d", len(st.Blocked))
	}
}

// --- removeAllowedState when file missing --------------------------------

func TestEngineRemoveAllowedStateEmptyFile(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	e.removeAllowedState("10.0.0.1")
	st := e.loadStateFile()
	if len(st.Allowed) != 0 {
		t.Errorf("Allowed should remain empty, got %d", len(st.Allowed))
	}
}

// --- removeSubnetState when file missing --------------------------------

func TestEngineRemoveSubnetStateEmptyFile(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	e.removeSubnetState("192.168.0.0/16")
	st := e.loadStateFile()
	if len(st.BlockedNet) != 0 {
		t.Errorf("BlockedNet should remain empty, got %d", len(st.BlockedNet))
	}
}

// --- saveAllowedEntry explicit Source preserved --------------------------

func TestEngineSaveAllowedEntryExplicitSourcePreserved(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	e.saveAllowedEntry(AllowedEntry{
		IP:     "10.0.0.1",
		Reason: "vpn",
		Source: "dyndns",
	})
	st := e.loadStateFile()
	if len(st.Allowed) != 1 || st.Allowed[0].Source != "dyndns" {
		t.Errorf("Source = %q, want dyndns", st.Allowed[0].Source)
	}
}

// --- saveSubnetEntry deduplicates exact CIDR (covers the dup branch) -----

func TestEngineSaveSubnetEntryDuplicateIgnored(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}
	e.saveSubnetEntry(SubnetEntry{CIDR: "10.0.0.0/8", Reason: "first", BlockedAt: time.Now()})
	e.saveSubnetEntry(SubnetEntry{CIDR: "10.0.0.0/8", Reason: "second", BlockedAt: time.Now()})

	st := e.loadStateFile()
	if len(st.BlockedNet) != 1 {
		t.Fatalf("BlockedNet = %d, want 1", len(st.BlockedNet))
	}
	if st.BlockedNet[0].Reason != "first" {
		t.Errorf("first reason should win, got %q", st.BlockedNet[0].Reason)
	}
}

// --- removeAllowedStateBySource when IP exists but source differs --------

func TestEngineRemoveAllowedStateBySourceSourceMismatch(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Source: "manual"})

	// Wrong source - should return false
	removed := e.removeAllowedStateBySource("10.0.0.1", "dyndns")
	if removed {
		t.Error("source mismatch should return false")
	}
	// Entry still present
	st := e.loadStateFile()
	if len(st.Allowed) != 1 {
		t.Errorf("Allowed = %d, want 1 (unchanged)", len(st.Allowed))
	}
}

// --- Status basic smoke without conn -------------------------------------

func TestEngineStatusEmptyState(t *testing.T) {
	e := &Engine{
		statePath: t.TempDir(),
		cfg: &FirewallConfig{
			Enabled:    true,
			TCPIn:      []int{22, 80},
			TCPOut:     []int{443},
			UDPIn:      []int{53},
			UDPOut:     []int{123},
			InfraIPs:   []string{"10.0.0.1"},
			LogDropped: true,
		},
	}
	s := e.Status()
	if s["enabled"] != true {
		t.Errorf("enabled = %v, want true", s["enabled"])
	}
	if s["blocked"] != 0 {
		t.Errorf("blocked = %v, want 0", s["blocked"])
	}
	if s["allowed"] != 0 {
		t.Errorf("allowed = %v, want 0", s["allowed"])
	}
	if s["log_dropped"] != true {
		t.Errorf("log_dropped = %v", s["log_dropped"])
	}
}

// --- loadStateFile: malformed JSON returns empty -------------------------

func TestEngineLoadStateFileMalformedJSONReturnsZero(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "state.json"), []byte("{{not json"), 0600)

	e := &Engine{statePath: dir}
	st := e.loadStateFile()
	if len(st.Blocked) != 0 || len(st.Allowed) != 0 || len(st.BlockedNet) != 0 {
		t.Error("malformed JSON should yield zero state")
	}
}

// --- CleanExpiredSubnets: only state mutation when any removed -----------

func TestEngineCleanExpiredSubnetsWithActiveOnly(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	// Write an explicitly active (far-future expiry) subnet directly to state
	future := time.Now().Add(24 * time.Hour)
	e.saveState(&FirewallState{
		BlockedNet: []SubnetEntry{{CIDR: "10.0.0.0/8", ExpiresAt: future}},
	})
	if n := e.CleanExpiredSubnets(); n != 0 {
		t.Errorf("CleanExpiredSubnets removed %d, want 0", n)
	}
	st := e.loadStateFile()
	if len(st.BlockedNet) != 1 {
		t.Errorf("active subnet should be preserved, got %d", len(st.BlockedNet))
	}
}

// --- saveBlockedEntry default source inference on empty Source -----------

func TestEngineSaveBlockedEntryInfersFromChallengeReason(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	e.saveBlockedEntry(BlockedEntry{
		IP:        "203.0.113.5",
		Reason:    "captcha challenge failed",
		BlockedAt: time.Now(),
	})
	st := e.loadStateFile()
	if len(st.Blocked) != 1 {
		t.Fatalf("Blocked = %d", len(st.Blocked))
	}
	if st.Blocked[0].Source == "" {
		t.Error("Source should be inferred")
	}
}
