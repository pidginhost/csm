//go:build linux

package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These tests run only on Linux where engine.go compiles.
// They test the state file management (JSON I/O) without needing nftables.

func TestEngineLoadStateFileEmpty(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}
	state := e.loadStateFile()
	if len(state.Blocked) != 0 {
		t.Errorf("empty dir should return empty state, got %d blocked", len(state.Blocked))
	}
}

func TestEngineLoadStateFileWithData(t *testing.T) {
	dir := t.TempDir()
	state := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.5", Reason: "brute-force", BlockedAt: time.Now()},
			{IP: "198.51.100.1", Reason: "waf", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(2 * time.Hour)},
		},
		Allowed: []AllowedEntry{
			{IP: "10.0.0.1", Reason: "admin"},
		},
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "state.json"), data, 0600)

	e := &Engine{statePath: dir}
	loaded := e.loadStateFile()
	if len(loaded.Blocked) != 2 {
		t.Errorf("got %d blocked, want 2", len(loaded.Blocked))
	}
	if len(loaded.Allowed) != 1 {
		t.Errorf("got %d allowed, want 1", len(loaded.Allowed))
	}
}

func TestEngineLoadStateFileExpiryCleanup(t *testing.T) {
	dir := t.TempDir()
	state := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.5", Reason: "active", BlockedAt: time.Now()},
			{IP: "198.51.100.1", Reason: "expired", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(-1 * time.Hour)},
		},
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "state.json"), data, 0600)

	e := &Engine{statePath: dir}
	loaded := e.loadStateFile()
	if len(loaded.Blocked) != 1 {
		t.Errorf("expired entry should be cleaned: got %d, want 1", len(loaded.Blocked))
	}
}

func TestEngineSaveState(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}
	state := &FirewallState{
		Blocked: []BlockedEntry{{IP: "1.2.3.4", Reason: "test"}},
	}
	e.saveState(state)

	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("state.json not written: %v", err)
	}
	if len(data) == 0 {
		t.Error("state.json should not be empty")
	}
}

func TestEngineSaveBlockedEntry(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.5", Reason: "test"})

	state := e.loadStateFile()
	if len(state.Blocked) != 1 {
		t.Errorf("got %d blocked, want 1", len(state.Blocked))
	}
}

func TestEngineSaveBlockedEntryDedup(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.5", Reason: "first"})
	e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.5", Reason: "second"})

	state := e.loadStateFile()
	if len(state.Blocked) != 1 {
		t.Errorf("dedup should keep 1, got %d", len(state.Blocked))
	}
	if state.Blocked[0].Reason != "second" {
		t.Errorf("should update reason, got %q", state.Blocked[0].Reason)
	}
}

func TestEngineRemoveBlockedState(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.5", Reason: "test"})
	e.removeBlockedState("203.0.113.5")

	state := e.loadStateFile()
	if len(state.Blocked) != 0 {
		t.Errorf("removed IP should be gone, got %d", len(state.Blocked))
	}
}

func TestEngineSaveAllowedEntry(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "admin"})

	state := e.loadStateFile()
	if len(state.Allowed) != 1 {
		t.Errorf("got %d allowed, want 1", len(state.Allowed))
	}
}

func TestEngineRemoveAllowedState(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveAllowedEntry(AllowedEntry{IP: "10.0.0.1", Reason: "admin"})
	e.removeAllowedState("10.0.0.1")

	state := e.loadStateFile()
	if len(state.Allowed) != 0 {
		t.Errorf("removed IP should be gone, got %d", len(state.Allowed))
	}
}

func TestEngineSaveSubnetEntry(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveSubnetEntry(SubnetEntry{CIDR: "192.168.0.0/16", Reason: "test"})

	state := e.loadStateFile()
	if len(state.BlockedNet) != 1 {
		t.Errorf("got %d subnets, want 1", len(state.BlockedNet))
	}
}

func TestEngineRemoveSubnetState(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}

	e.saveSubnetEntry(SubnetEntry{CIDR: "192.168.0.0/16", Reason: "test"})
	e.removeSubnetState("192.168.0.0/16")

	state := e.loadStateFile()
	if len(state.BlockedNet) != 0 {
		t.Errorf("removed subnet should be gone, got %d", len(state.BlockedNet))
	}
}

func TestEngineStatus(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		statePath: dir,
		cfg:       &FirewallConfig{Enabled: true, TCPIn: []int{22, 80}},
	}

	status := e.Status()
	if status == nil {
		t.Fatal("status should not be nil")
	}
}
