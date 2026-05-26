package checks

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// outcomeIPBlocker simulates an engine that reports BlockIPOutcome.
// outcome is the value returned by BlockIPOutcome; blockErr lets a test
// inject an error from the engine.
type outcomeIPBlocker struct {
	blocked     []blockCall
	outcome     firewall.BlockOutcome
	blockErr    error
	outcomeHits int
	legacyHits  int
}

func (b *outcomeIPBlocker) BlockIP(ip, reason string, timeout time.Duration) error {
	b.legacyHits++
	b.blocked = append(b.blocked, blockCall{ip: ip, reason: reason, timeout: timeout})
	return b.blockErr
}

func (b *outcomeIPBlocker) UnblockIP(ip string) error { return nil }

func (b *outcomeIPBlocker) IsBlocked(ip string) bool { return false }

func (b *outcomeIPBlocker) BlockIPOutcome(ip, reason string, timeout time.Duration) (firewall.BlockOutcome, error) {
	b.outcomeHits++
	b.blocked = append(b.blocked, blockCall{ip: ip, reason: reason, timeout: timeout})
	return b.outcome, b.blockErr
}

func newAutoBlockTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	return cfg
}

func swapBlocker(t *testing.T, b IPBlocker) {
	t.Helper()
	old := fwBlocker
	SetIPBlocker(b)
	t.Cleanup(func() { SetIPBlocker(old) })
}

// TestAutoBlockIPs_DryRunOutcome_DoesNotMutateState asserts that when the
// firewall engine reports BlockOutcomeDryRun, the auto-block path does NOT
// write the IP to blocked_ips.json, does NOT bump BlocksThisHour, and emits
// a dry-run-specific finding (not the "AUTO-BLOCK: X blocked" Critical that
// claims a real block happened).
func TestAutoBlockIPs_DryRunOutcome_DoesNotMutateState(t *testing.T) {
	cfg := newAutoBlockTestConfig(t)
	blocker := &outcomeIPBlocker{outcome: firewall.BlockOutcomeDryRun}
	swapBlocker(t, blocker)

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:     "wp_login_bruteforce",
		Message:   "WordPress brute force from 192.0.2.10",
		Timestamp: time.Now(),
	}})

	if blocker.outcomeHits != 1 {
		t.Fatalf("BlockIPOutcome calls = %d, want 1", blocker.outcomeHits)
	}
	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 0 {
		t.Errorf("state.IPs grew on dry-run: %+v", state.IPs)
	}
	if state.BlocksThisHour != 0 {
		t.Errorf("state.BlocksThisHour = %d on dry-run, want 0", state.BlocksThisHour)
	}
	if len(actions) != 1 {
		t.Fatalf("actions count = %d, want 1 (dry-run notice)", len(actions))
	}
	a := actions[0]
	if a.Severity != alert.Warning {
		t.Errorf("dry-run finding severity = %v, want Warning", a.Severity)
	}
	if !strings.Contains(a.Message, "dry-run") && !strings.Contains(a.Message, "DRY-RUN") {
		t.Errorf("dry-run finding message lacks dry-run marker: %q", a.Message)
	}
	if strings.HasPrefix(a.Message, "AUTO-BLOCK:") {
		t.Errorf("dry-run finding must not use 'AUTO-BLOCK:' prefix (filters treat it as a real block): %q", a.Message)
	}
}

// TestAutoBlockIPs_VerdictAllowOutcome_DoesNotMutateState asserts that when
// the engine's verdict callback returned "allow" (BlockOutcomeAllowed), no
// state mutation occurs and no AUTO-BLOCK finding is emitted.
func TestAutoBlockIPs_VerdictAllowOutcome_DoesNotMutateState(t *testing.T) {
	cfg := newAutoBlockTestConfig(t)
	blocker := &outcomeIPBlocker{outcome: firewall.BlockOutcomeAllowed}
	swapBlocker(t, blocker)

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:     "wp_login_bruteforce",
		Message:   "WordPress brute force from 192.0.2.20",
		Timestamp: time.Now(),
	}})

	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 0 {
		t.Errorf("state.IPs grew on verdict-allow: %+v", state.IPs)
	}
	if state.BlocksThisHour != 0 {
		t.Errorf("state.BlocksThisHour = %d on verdict-allow, want 0", state.BlocksThisHour)
	}
	for _, a := range actions {
		if strings.HasPrefix(a.Message, "AUTO-BLOCK:") {
			t.Errorf("verdict-allow path must not emit AUTO-BLOCK finding: %q", a.Message)
		}
	}
}

func TestAutoBlockIPs_UnknownOutcome_DoesNotMutateState(t *testing.T) {
	cfg := newAutoBlockTestConfig(t)
	blocker := &outcomeIPBlocker{outcome: firewall.BlockOutcome("")}
	swapBlocker(t, blocker)

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:     "wp_login_bruteforce",
		Message:   "WordPress brute force from 192.0.2.25",
		Timestamp: time.Now(),
	}})

	if blocker.outcomeHits != 1 {
		t.Fatalf("BlockIPOutcome calls = %d, want 1", blocker.outcomeHits)
	}
	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 0 {
		t.Errorf("state.IPs grew on unknown outcome: %+v", state.IPs)
	}
	if state.BlocksThisHour != 0 {
		t.Errorf("state.BlocksThisHour = %d on unknown outcome, want 0", state.BlocksThisHour)
	}
	if len(actions) != 0 {
		t.Fatalf("actions count = %d, want 0 for unknown outcome: %+v", len(actions), actions)
	}
}

// TestAutoBlockIPs_LiveOutcome_MutatesState verifies the happy path is
// unchanged: a Live outcome causes state.IPs to grow, BlocksThisHour to
// increment, and the existing Critical "AUTO-BLOCK: X blocked" finding to
// be emitted.
func TestAutoBlockIPs_LiveOutcome_MutatesState(t *testing.T) {
	cfg := newAutoBlockTestConfig(t)
	blocker := &outcomeIPBlocker{outcome: firewall.BlockOutcomeLive}
	swapBlocker(t, blocker)

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:     "wp_login_bruteforce",
		Message:   "WordPress brute force from 192.0.2.30",
		Timestamp: time.Now(),
	}})

	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 1 {
		t.Fatalf("state.IPs len = %d, want 1", len(state.IPs))
	}
	if state.IPs[0].IP != "192.0.2.30" {
		t.Errorf("blocked IP = %q, want 192.0.2.30", state.IPs[0].IP)
	}
	if state.BlocksThisHour != 1 {
		t.Errorf("state.BlocksThisHour = %d, want 1", state.BlocksThisHour)
	}
	if len(actions) != 1 {
		t.Fatalf("actions count = %d, want 1", len(actions))
	}
	if actions[0].Severity != alert.Critical {
		t.Errorf("live finding severity = %v, want Critical", actions[0].Severity)
	}
	if !strings.HasPrefix(actions[0].Message, "AUTO-BLOCK:") {
		t.Errorf("live finding message must start with 'AUTO-BLOCK:', got %q", actions[0].Message)
	}
}

// liveOnlyBlocker implements IPBlocker plus the optional liveBlocker
// shape. The reconcile loop should prefer IsBlockedLive over IsBlocked,
// so a tracker entry whose live counterpart has expired must be pruned
// even when the cached IsBlocked view still claims it is blocked.
type liveOnlyBlocker struct {
	cachedSays bool
	liveSays   bool
	liveErr    error
	liveCalls  int
	blocks     int
}

func (b *liveOnlyBlocker) BlockIP(ip, reason string, timeout time.Duration) error {
	b.blocks++
	return nil
}
func (b *liveOnlyBlocker) UnblockIP(ip string) error { return nil }
func (b *liveOnlyBlocker) IsBlocked(ip string) bool  { return b.cachedSays }
func (b *liveOnlyBlocker) IsBlockedLive(ip string) (bool, error) {
	b.liveCalls++
	return b.liveSays, b.liveErr
}

// TestAutoBlockIPs_ReconcilePrefersLiveStatus regression-guards F10:
// blocked_ips.json must shrink to match the live kernel set, not the
// possibly-stale state.json cache the engine exposes via IsBlocked.
func TestAutoBlockIPs_ReconcilePrefersLiveStatus(t *testing.T) {
	cfg := newAutoBlockTestConfig(t)
	cfg.AutoResponse.Enabled = false // keep block path inert; only test the reconcile prune
	cfg.AutoResponse.BlockIPs = false

	// Seed a tracker entry directly on disk.
	seed := &blockState{
		IPs: []blockedIP{{IP: "192.0.2.55", Reason: "test", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}},
	}
	saveBlockState(cfg.StatePath, seed)

	// Cached view still says "blocked"; live view says "expired".
	blocker := &liveOnlyBlocker{cachedSays: true, liveSays: false}
	swapBlocker(t, blocker)

	// Re-enable the reconcile-only branch by flipping back on for the call.
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	_ = AutoBlockIPs(cfg, nil)

	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 0 {
		t.Errorf("expected tracker pruned by live kernel state, still holds %+v", state.IPs)
	}
	if blocker.liveCalls == 0 {
		t.Error("reconcile loop should have consulted IsBlockedLive at least once")
	}
}

func TestAutoBlockIPs_ReconcileFallsBackToCachedStatusOnLiveError(t *testing.T) {
	cfg := newAutoBlockTestConfig(t)

	seed := &blockState{
		IPs: []blockedIP{{IP: "192.0.2.56", Reason: "test", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}},
	}
	saveBlockState(cfg.StatePath, seed)

	blocker := &liveOnlyBlocker{
		cachedSays: true,
		liveErr:    errors.New("netlink unavailable"),
	}
	swapBlocker(t, blocker)

	_ = AutoBlockIPs(cfg, nil)

	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 1 || state.IPs[0].IP != "192.0.2.56" {
		t.Fatalf("live lookup error should keep cached tracker entry, got %+v", state.IPs)
	}
	if blocker.liveCalls == 0 {
		t.Fatal("reconcile loop should have attempted the live lookup")
	}
}

func TestAutoBlockIPs_ReblocksWhenLiveSetLostCachedBlock(t *testing.T) {
	cfg := newAutoBlockTestConfig(t)

	seed := &blockState{
		IPs: []blockedIP{{IP: "192.0.2.57", Reason: "old", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}},
	}
	saveBlockState(cfg.StatePath, seed)

	blocker := &liveOnlyBlocker{cachedSays: true, liveSays: false}
	swapBlocker(t, blocker)

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:     "wp_login_bruteforce",
		Message:   "WordPress brute force from 192.0.2.57",
		Timestamp: time.Now(),
	}})

	if blocker.blocks != 1 {
		t.Fatalf("cached stale block should be re-applied once, block calls = %d", blocker.blocks)
	}
	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 1 || state.IPs[0].IP != "192.0.2.57" {
		t.Fatalf("expected tracker to contain re-blocked IP, got %+v", state.IPs)
	}
	if len(actions) != 1 || !strings.HasPrefix(actions[0].Message, "AUTO-BLOCK:") {
		t.Fatalf("expected one live auto-block action, got %+v", actions)
	}
}

// TestAutoBlockIPs_LegacyBlockerStillSupported keeps the back-compat path
// honest: a blocker that only implements IPBlocker (no BlockIPOutcome)
// should behave as before (Live semantics, state mutated).
func TestAutoBlockIPs_LegacyBlockerStillSupported(t *testing.T) {
	cfg := newAutoBlockTestConfig(t)
	blocker := &recordingIPBlocker{}
	swapBlocker(t, blocker)

	actions := AutoBlockIPs(cfg, []alert.Finding{{
		Check:     "wp_login_bruteforce",
		Message:   "WordPress brute force from 192.0.2.40",
		Timestamp: time.Now(),
	}})

	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 1 {
		t.Fatalf("state.IPs len = %d, want 1", len(state.IPs))
	}
	if len(actions) != 1 {
		t.Fatalf("actions count = %d, want 1", len(actions))
	}
	if actions[0].Severity != alert.Critical {
		t.Errorf("legacy live finding severity = %v, want Critical", actions[0].Severity)
	}
}
