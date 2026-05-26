//go:build linux

package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestEngineBlockedCount_ReadsStateFile asserts that BlockedCount reports
// the engine's live count of blocked IPs sourced from the engine state
// file, since that is the authoritative store production writes to. The
// /api/v1/status surface previously read a parallel bbolt bucket that
// production never wrote, and reported stale counts to phpanel.
func TestEngineBlockedCount_ReadsStateFile(t *testing.T) {
	dir := t.TempDir()
	state := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.10", Reason: "wp_bruteforce", BlockedAt: time.Now()},
			{IP: "203.0.113.11", Reason: "ua_spoof", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(2 * time.Hour)},
			{IP: "198.51.100.5", Reason: "xmlrpc", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(1 * time.Hour)},
		},
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0600); err != nil {
		t.Fatalf("write state.json: %v", err)
	}

	e := &Engine{statePath: dir}
	got := e.BlockedCount()
	if got != 3 {
		t.Errorf("BlockedCount = %d, want 3", got)
	}
}

func TestEngineBlockedCount_ExpiredEntriesNotCounted(t *testing.T) {
	dir := t.TempDir()
	state := FirewallState{
		Blocked: []BlockedEntry{
			{IP: "203.0.113.12", Reason: "active", BlockedAt: time.Now()},
			{IP: "198.51.100.6", Reason: "expired", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(-1 * time.Hour)},
		},
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0600); err != nil {
		t.Fatalf("write state.json: %v", err)
	}

	e := &Engine{statePath: dir}
	got := e.BlockedCount()
	if got != 1 {
		t.Errorf("BlockedCount = %d, want 1 (expired entry must not count)", got)
	}
}

func TestEngineBlockedCount_MissingStateFileReturnsZero(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{statePath: dir}
	if got := e.BlockedCount(); got != 0 {
		t.Errorf("BlockedCount with no state.json = %d, want 0", got)
	}
}
