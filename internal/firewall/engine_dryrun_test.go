//go:build linux

package firewall

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// TestBlockIP_DryRunDoesNotCallRecorder_WhenDryRunOff verifies that when
// auto_response.dry_run is false, BlockIP does NOT invoke the recorder.
// (It will attempt the real nftables call and panic on nil conn -- the panic
// recovery confirms we reached the nftables path, not the dry-run path.)
func TestBlockIP_DryRunDoesNotCallRecorder_WhenDryRunOff(t *testing.T) {
	dr := false
	cfg := &config.Config{}
	cfg.AutoResponse.DryRun = &dr
	config.SetActive(cfg)
	defer config.SetActive(nil)

	recorded := false
	e := &Engine{
		cfg:      &FirewallConfig{Enabled: true},
		statePath: t.TempDir(),
		dryRunRecorder: func(ip, reason string, timeout time.Duration) {
			recorded = true
		},
	}

	// BlockIP should NOT enter the dry-run branch (will panic on nil conn).
	defer func() {
		if r := recover(); r == nil {
			// No panic means the call returned without hitting nftables --
			// which would only happen if dry-run intercepted it (wrong branch).
			t.Error("expected panic from nil conn (live path), got nil -- dry-run gate fired incorrectly")
		}
		// Panic is expected: we reached the nftables path, which is correct.
	}()
	_ = e.BlockIP("192.0.2.1", "test", 0)

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
	dr := true
	cfg := &config.Config{}
	cfg.AutoResponse.DryRun = &dr
	config.SetActive(cfg)
	defer config.SetActive(nil)

	var gotIP, gotReason string
	var gotTimeout time.Duration
	e := &Engine{
		cfg:      &FirewallConfig{Enabled: true},
		statePath: t.TempDir(),
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

// TestBlockIPForce_IgnoresDryRun verifies that BlockIPForce bypasses the
// dry_run gate and attempts the real nftables path (panics on nil conn).
func TestBlockIPForce_IgnoresDryRun(t *testing.T) {
	dr := true
	cfg := &config.Config{}
	cfg.AutoResponse.DryRun = &dr
	config.SetActive(cfg)
	defer config.SetActive(nil)

	recorded := false
	e := &Engine{
		cfg:      &FirewallConfig{Enabled: true},
		statePath: t.TempDir(),
		dryRunRecorder: func(ip, reason string, timeout time.Duration) {
			recorded = true
		},
	}

	// BlockIPForce must not enter dry-run; it should panic on nil conn.
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic from nil conn in BlockIPForce (no dry-run), got nil")
		}
	}()
	_ = e.BlockIPForce("192.0.2.2", "operator-block", 0)

	if recorded {
		t.Error("recorder was called by BlockIPForce -- should bypass dry-run")
	}
}

// TestBlockIP_DryRunDefault_NilActiveConfig verifies that when config.Active()
// is nil (early startup, tests), BlockIP proceeds to the live nftables path.
func TestBlockIP_DryRunDefault_NilActiveConfig(t *testing.T) {
	config.SetActive(nil)

	e := &Engine{
		cfg:      &FirewallConfig{Enabled: true},
		statePath: t.TempDir(),
	}

	// Nil Active() means live path: should panic on nil conn.
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic from nil conn when Active()=nil, got nil")
		}
	}()
	_ = e.BlockIP("192.0.2.3", "test", 0)
}
