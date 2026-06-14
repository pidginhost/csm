//go:build linux

package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFirewallStateForTest(t *testing.T, dir string, st FirewallState) {
	t.Helper()
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0600); err != nil {
		t.Fatalf("write state: %v", err)
	}
}

// An auto-block must never re-block an IP the operator put on allowed_ips.
// The nftables input chain drops @blocked_ips before it accepts @allowed_ips,
// so the only safe fix is to keep the allowlisted IP out of blocked_ips in the
// first place. BlockIPOutcome is the single auto-block entry point; it must
// short-circuit to BlockOutcomeAllowlisted before any kernel mutation.
func TestBlockIPOutcome_SkipsAllowedIP(t *testing.T) {
	dir := t.TempDir()
	writeFirewallStateForTest(t, dir, FirewallState{
		Allowed: []AllowedEntry{{IP: "203.0.113.50", Reason: "operator allow"}},
	})
	e := &Engine{
		cfg:       &FirewallConfig{Enabled: true},
		statePath: dir,
		// dry-run on so a guard that fails to fire yields DryRun (not a nil-conn
		// panic), giving a clean assertion failure instead of a crash.
		dryRunEnabled: func() bool { return true },
	}

	outcome, err := e.BlockIPOutcome("203.0.113.50", "auto", time.Hour)
	if err != nil {
		t.Fatalf("BlockIPOutcome returned error: %v", err)
	}
	if outcome != BlockOutcomeAllowlisted {
		t.Fatalf("outcome = %q, want %q (allowlisted IP must not be auto-blocked)", outcome, BlockOutcomeAllowlisted)
	}
}

// Verified-bot ranges reach the engine through the soft-allow checker the
// daemon wires (the engine itself does not import threatintel). A claimed-bot
// IP in a published range must be skipped by the auto-block path.
func TestBlockIPOutcome_SkipsSoftAllowedRange(t *testing.T) {
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true},
		statePath:     t.TempDir(),
		dryRunEnabled: func() bool { return true },
	}
	e.SetSoftAllowChecker(func(ip string) bool { return ip == "198.51.100.7" })

	outcome, err := e.BlockIPOutcome("198.51.100.7", "auto", time.Hour)
	if err != nil {
		t.Fatalf("BlockIPOutcome returned error: %v", err)
	}
	if outcome != BlockOutcomeAllowlisted {
		t.Fatalf("outcome = %q, want %q (verified-bot IP must not be auto-blocked)", outcome, BlockOutcomeAllowlisted)
	}
}

// The guard must not over-fire: an IP that is neither allowlisted nor a
// verified bot proceeds through the normal gates (dry-run here).
func TestBlockIPOutcome_NonAllowlistedProceeds(t *testing.T) {
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true},
		statePath:     t.TempDir(),
		dryRunEnabled: func() bool { return true },
	}
	e.SetSoftAllowChecker(func(ip string) bool { return false })

	outcome, err := e.BlockIPOutcome("198.51.100.9", "auto", time.Hour)
	if err != nil {
		t.Fatalf("BlockIPOutcome returned error: %v", err)
	}
	if outcome != BlockOutcomeDryRun {
		t.Fatalf("outcome = %q, want %q (non-allowlisted IP must reach the dry-run gate)", outcome, BlockOutcomeDryRun)
	}
}

func TestIsAllowed_ReadsState(t *testing.T) {
	dir := t.TempDir()
	writeFirewallStateForTest(t, dir, FirewallState{
		Allowed: []AllowedEntry{{IP: "203.0.113.50", Reason: "operator allow"}},
	})
	e := &Engine{cfg: &FirewallConfig{Enabled: true}, statePath: dir}

	if !e.IsAllowed("203.0.113.50") {
		t.Error("IsAllowed should report a state-file allowed IP as allowed")
	}
	if e.IsAllowed("203.0.113.51") {
		t.Error("IsAllowed must not report an unrelated IP as allowed")
	}
}
