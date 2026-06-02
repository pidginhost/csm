//go:build linux

package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// When the temporary-deny cap is reached, the eviction policy must pick the
// block closest to expiry so a fresh block (a real attacker) always fits. This
// is what stops an attacker from saturating the cap with throwaway IPs to
// shield the IPs doing real damage.
func TestSoonestExpiringTempIP(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	st := FirewallState{Blocked: []BlockedEntry{
		{IP: "192.0.2.1"}, // permanent: never evicted here
		{IP: "192.0.2.2", ExpiresAt: now.Add(time.Hour)},
		{IP: "192.0.2.3", ExpiresAt: now.Add(10 * time.Minute)}, // soonest
		{IP: "192.0.2.4", ExpiresAt: now.Add(30 * time.Minute)},
	}}

	got, ok := soonestExpiringTempIP(st, "")
	if !ok || got != "192.0.2.3" {
		t.Fatalf("soonest-expiring temp = %q (ok=%v), want 192.0.2.3", got, ok)
	}

	// The IP being blocked now must not be chosen as its own victim.
	got, ok = soonestExpiringTempIP(st, "192.0.2.3")
	if !ok || got != "192.0.2.4" {
		t.Fatalf("with exclude, soonest = %q (ok=%v), want 192.0.2.4", got, ok)
	}
}

// With only permanent blocks there is nothing to evict, so the caller keeps
// refusing rather than removing an operator's permanent block.
func TestSoonestExpiringTempIP_NoTempEntries(t *testing.T) {
	st := FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.1"}}}
	if _, ok := soonestExpiringTempIP(st, ""); ok {
		t.Fatal("permanent-only state must report no temp entry to evict")
	}
}

func TestBlockIPOutcome_DryRunAtTempCapDoesNotEvict(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true, DenyTempIPLimit: 1},
		statePath:     dir,
		dryRunEnabled: func() bool { return true },
	}
	if err := e.saveBlockedEntry(BlockedEntry{
		IP:        "192.0.2.10",
		Reason:    "existing temp block",
		BlockedAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed block: %v", err)
	}

	outcome, err := e.BlockIPOutcome("192.0.2.11", "new temp block", time.Hour)
	if err != nil {
		t.Fatalf("BlockIPOutcome: %v", err)
	}
	if outcome != BlockOutcomeDryRun {
		t.Fatalf("outcome = %q, want %q", outcome, BlockOutcomeDryRun)
	}
	assertOnlyBlockedIP(t, e, "192.0.2.10")
	assertNoAuditLog(t, dir)
}

func TestBlockIPOutcome_AllowVerdictAtTempCapDoesNotEvict(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		cfg:       &FirewallConfig{Enabled: true, DenyTempIPLimit: 1},
		statePath: dir,
		verdictAsker: func(_ context.Context, _, _ string) (string, string, string, error) {
			return "allow", "", "", nil
		},
	}
	if err := e.saveBlockedEntry(BlockedEntry{
		IP:        "192.0.2.20",
		Reason:    "existing temp block",
		BlockedAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed block: %v", err)
	}

	outcome, err := e.BlockIPOutcome("192.0.2.21", "new temp block", time.Hour)
	if err != nil {
		t.Fatalf("BlockIPOutcome: %v", err)
	}
	if outcome != BlockOutcomeAllowed {
		t.Fatalf("outcome = %q, want %q", outcome, BlockOutcomeAllowed)
	}
	assertOnlyBlockedIP(t, e, "192.0.2.20")
	assertNoAuditLog(t, dir)
}

func assertOnlyBlockedIP(t *testing.T, e *Engine, ip string) {
	t.Helper()
	state := e.loadStateFile()
	if len(state.Blocked) != 1 {
		t.Fatalf("blocked entries = %d, want 1: %#v", len(state.Blocked), state.Blocked)
	}
	if state.Blocked[0].IP != ip {
		t.Fatalf("blocked IP = %q, want %q", state.Blocked[0].IP, ip)
	}
}

func assertNoAuditLog(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, "audit.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("audit log exists or stat failed: %v", err)
	}
}
