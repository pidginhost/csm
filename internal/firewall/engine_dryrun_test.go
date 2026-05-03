//go:build linux

package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBlockIP_DryRunDoesNotCallRecorder_WhenDryRunOff(t *testing.T) {
	recorded := false
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true},
		statePath:     t.TempDir(),
		dryRunEnabled: func() bool { return false },
		dryRunRecorder: func(ip, reason string, timeout time.Duration) {
			recorded = true
		},
	}

	err := e.BlockIP("not-an-ip", "test", 0)
	if err == nil || !strings.Contains(err.Error(), "invalid IP") {
		t.Fatalf("expected invalid IP error from live validation path, got %v", err)
	}

	if recorded {
		t.Error("recorder was called even though dry_run=false")
	}
}

// TestBlockIP_DryRunRecordsAndReturnsNil verifies that when
// auto_response.dry_run is true, BlockIP:
//   - invokes the dryRunRecorder with the correct ip/reason/timeout
//   - returns nil (caller proceeds normally)
//   - does NOT touch nftables (nil conn does not panic)
func TestBlockIP_DryRunRecordsAndReturnsNil(t *testing.T) {
	var gotIP, gotReason string
	var gotTimeout time.Duration
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true},
		statePath:     t.TempDir(),
		dryRunEnabled: func() bool { return true },
		dryRunRecorder: func(ip, reason string, timeout time.Duration) {
			gotIP = ip
			gotReason = reason
			gotTimeout = timeout
		},
	}

	err := e.BlockIP("192.0.2.1", "brute-force", time.Hour)
	if err != nil {
		t.Fatalf("expected nil error in dry-run, got %v", err)
	}
	if gotIP != "192.0.2.1" {
		t.Errorf("recorder ip = %q, want 192.0.2.1", gotIP)
	}
	if gotReason != "brute-force" {
		t.Errorf("recorder reason = %q, want brute-force", gotReason)
	}
	if gotTimeout != time.Hour {
		t.Errorf("recorder timeout = %v, want 1h", gotTimeout)
	}
}

func TestBlockIPForce_IgnoresDryRun(t *testing.T) {
	recorded := false
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true},
		statePath:     t.TempDir(),
		dryRunEnabled: func() bool { return true },
		dryRunRecorder: func(ip, reason string, timeout time.Duration) {
			recorded = true
		},
	}

	err := e.BlockIPForce("not-an-ip", "operator-block", 0)
	if err == nil || !strings.Contains(err.Error(), "invalid IP") {
		t.Fatalf("expected invalid IP error from forced live path, got %v", err)
	}

	if recorded {
		t.Error("recorder was called by BlockIPForce -- should bypass dry-run")
	}
}

func TestBlockIP_DryRunDefault_NoCallback(t *testing.T) {
	e := &Engine{
		cfg:       &FirewallConfig{Enabled: true},
		statePath: t.TempDir(),
	}

	err := e.BlockIP("not-an-ip", "test", 0)
	if err == nil || !strings.Contains(err.Error(), "invalid IP") {
		t.Fatalf("expected invalid IP error when dry-run callback is nil, got %v", err)
	}
}

func TestBlockIP_DryRunPreservesInfraSafetyCheck(t *testing.T) {
	recorded := false
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true, InfraIPs: []string{"192.0.2.0/24"}},
		statePath:     t.TempDir(),
		dryRunEnabled: func() bool { return true },
		dryRunRecorder: func(ip, reason string, timeout time.Duration) {
			recorded = true
		},
	}

	err := e.BlockIP("192.0.2.3", "test", 0)
	if err == nil || !strings.Contains(err.Error(), "refusing to block infra IP") {
		t.Fatalf("expected infra safety error in dry-run path, got %v", err)
	}
	if recorded {
		t.Fatal("dry-run recorder was called for an IP live blocking would refuse")
	}
}

func TestBlockIP_VerdictAllowShortCircuits(t *testing.T) {
	called := 0
	e := &Engine{
		cfg:       &FirewallConfig{Enabled: true},
		statePath: t.TempDir(),
		verdictAsker: func(_ context.Context, ip, reason string) (string, string, string, error) {
			called++
			return "allow", "tenant-1", "test-note", nil
		},
	}
	if err := e.BlockIP("192.0.2.1", "test", 0); err != nil {
		t.Fatalf("expected nil error on verdict allow, got %v", err)
	}
	if called != 1 {
		t.Fatalf("expected verdict asker called once, got %d", called)
	}
}

func TestBlockIP_VerdictErrorProceedsToDefault(t *testing.T) {
	called := 0
	recorded := false
	e := &Engine{
		cfg:       &FirewallConfig{Enabled: true},
		statePath: t.TempDir(),
		verdictAsker: func(_ context.Context, ip, reason string) (string, string, string, error) {
			called++
			return "", "", "", errors.New("network down")
		},
		dryRunEnabled: func() bool { return true },
		dryRunRecorder: func(ip, reason string, timeout time.Duration) {
			recorded = true
		},
	}
	err := e.BlockIP("192.0.2.1", "test", 0)
	if err != nil {
		t.Fatalf("expected verdict error to fail open into dry-run path, got %v", err)
	}
	if called != 1 {
		t.Fatalf("expected verdict asker called once, got %d", called)
	}
	if !recorded {
		t.Fatal("expected dry-run recorder after verdict error")
	}
}

func TestBlockIP_VerdictBlockProceedsToDefault(t *testing.T) {
	called := 0
	recorded := false
	e := &Engine{
		cfg:       &FirewallConfig{Enabled: true},
		statePath: t.TempDir(),
		verdictAsker: func(_ context.Context, ip, reason string) (string, string, string, error) {
			called++
			return "block", "tenant-1", "test-note", nil
		},
		dryRunEnabled: func() bool { return true },
		dryRunRecorder: func(ip, reason string, timeout time.Duration) {
			recorded = true
		},
	}
	err := e.BlockIP("192.0.2.1", "test", 0)
	if err != nil {
		t.Fatalf("expected verdict block to continue into dry-run path, got %v", err)
	}
	if called != 1 {
		t.Fatalf("expected verdict asker called once, got %d", called)
	}
	if !recorded {
		t.Fatal("expected dry-run recorder after verdict block")
	}
}

func TestBlockIP_VerdictNotCalledWhenLocalValidationFails(t *testing.T) {
	called := false
	e := &Engine{
		cfg:       &FirewallConfig{Enabled: true, InfraIPs: []string{"192.0.2.0/24"}},
		statePath: t.TempDir(),
		verdictAsker: func(_ context.Context, ip, reason string) (string, string, string, error) {
			called = true
			return "allow", "", "", nil
		},
		dryRunEnabled: func() bool { return true },
	}
	err := e.BlockIP("192.0.2.10", "test", 0)
	if err == nil || !strings.Contains(err.Error(), "refusing to block infra IP") {
		t.Fatalf("expected infra safety error before verdict callback, got %v", err)
	}
	if called {
		t.Fatal("verdict callback was called for a locally refused block")
	}
}

func TestBlockIP_VerdictAllowDoesNotHideInvalidIP(t *testing.T) {
	called := false
	e := &Engine{
		cfg:       &FirewallConfig{Enabled: true},
		statePath: t.TempDir(),
		verdictAsker: func(_ context.Context, ip, reason string) (string, string, string, error) {
			called = true
			return "allow", "", "", nil
		},
	}
	err := e.BlockIP("not-an-ip", "test", 0)
	if err == nil || !strings.Contains(err.Error(), "invalid IP") {
		t.Fatalf("expected invalid IP error before verdict callback, got %v", err)
	}
	if called {
		t.Fatal("verdict callback was called for invalid IP")
	}
}
