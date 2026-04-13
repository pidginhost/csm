//go:build integration

package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

func TestCheckSuiteOnRealSystem(t *testing.T) {
	cfg := &config.Config{
		StatePath: t.TempDir(),
		Firewall:  &firewall.FirewallConfig{},
	}
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Run the critical check tier on the real system
	checks.ForceAll = false
	findings := checks.RunTier(cfg, store, checks.TierCritical)
	t.Logf("Critical tier produced %d findings on this host", len(findings))

	// Just verify it ran without panicking — on a fresh server
	// most checks will produce 0 or informational findings.
}

func TestRunAllChecksOnRealSystem(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full check suite in short mode")
	}

	cfg := &config.Config{
		StatePath: t.TempDir(),
		Firewall:  &firewall.FirewallConfig{},
	}
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	checks.ForceAll = true
	defer func() { checks.ForceAll = false }()

	findings := checks.RunAll(cfg, store)
	t.Logf("RunAll produced %d findings on this host", len(findings))

	// Categorize findings
	critical, high, warning := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case 2:
			critical++
		case 1:
			high++
		case 0:
			warning++
		}
	}
	t.Logf("  Critical: %d, High: %d, Warning: %d", critical, high, warning)
}

func TestCSMInstallVerification(t *testing.T) {
	// Verify CSM binary exists and config is valid
	if _, err := os.Stat("/opt/csm/csm"); err != nil {
		t.Skip("CSM not installed — skipping install verification")
	}

	// Verify config loads
	cfg, err := config.Load("/opt/csm/csm.yaml")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Hostname == "" {
		t.Error("hostname should not be empty after install")
	}

	t.Logf("CSM installed: hostname=%s", cfg.Hostname)
}

func TestHardeningAuditOnRealSystem(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	report := checks.RunHardeningAudit(cfg)
	if report == nil {
		t.Fatal("hardening audit should return non-nil report")
	}

	pass, fail, warn := 0, 0, 0
	for _, r := range report.Results {
		switch r.Status {
		case "pass":
			pass++
		case "fail":
			fail++
		case "warn":
			warn++
		}
	}
	t.Logf("Hardening audit: %d pass, %d fail, %d warn (total %d)",
		pass, fail, warn, len(report.Results))

	if len(report.Results) == 0 {
		t.Error("hardening audit should produce results on a real system")
	}
}

func TestRealLoadAverage(t *testing.T) {
	cfg := &config.Config{}
	findings := checks.CheckLoadAverage(context.Background(), cfg, nil)
	// On a fresh idle server, load should be low — 0 findings expected.
	t.Logf("LoadAverage produced %d findings", len(findings))
}

func TestRealKernelModules(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := checks.CheckKernelModules(context.Background(), &config.Config{}, store)
	// First run = baseline
	t.Logf("KernelModules (baseline): %d findings", len(findings))
}

func TestRealUID0Accounts(t *testing.T) {
	findings := checks.CheckUID0Accounts(context.Background(), &config.Config{}, nil)
	t.Logf("UID0Accounts: %d findings", len(findings))
	// Fresh server should only have root as UID 0
}

func TestRealHealthCheck(t *testing.T) {
	findings := checks.CheckHealth(context.Background(), &config.Config{}, nil)
	t.Logf("Health check: %d findings", len(findings))
}

func TestRealSwapAndOOM(t *testing.T) {
	findings := checks.CheckSwapAndOOM(context.Background(), &config.Config{}, nil)
	t.Logf("SwapAndOOM: %d findings", len(findings))
}

func TestRealOutboundConnections(t *testing.T) {
	findings := checks.CheckOutboundUserConnections(context.Background(), &config.Config{}, nil)
	t.Logf("OutboundConnections: %d findings", len(findings))
}

func TestRealRPMIntegrity(t *testing.T) {
	findings := checks.CheckRPMIntegrity(context.Background(), &config.Config{}, nil)
	t.Logf("RPMIntegrity: %d findings", len(findings))
}

func TestRealFakeKernelThreads(t *testing.T) {
	findings := checks.CheckFakeKernelThreads(context.Background(), &config.Config{}, nil)
	t.Logf("FakeKernelThreads: %d findings", len(findings))
	// Fresh server should have 0 — all kernel threads have UID 0
	if len(findings) != 0 {
		t.Errorf("fresh server should have 0 fake kernel threads, got %d", len(findings))
	}
}

func TestRealSuspiciousProcesses(t *testing.T) {
	findings := checks.CheckSuspiciousProcesses(context.Background(), &config.Config{}, nil)
	t.Logf("SuspiciousProcesses: %d findings", len(findings))
}

func TestRealDNSConnections(t *testing.T) {
	findings := checks.CheckDNSConnections(context.Background(), &config.Config{}, nil)
	t.Logf("DNSConnections: %d findings", len(findings))
}

func TestRealPHPProcesses(t *testing.T) {
	findings := checks.CheckPHPProcesses(context.Background(), &config.Config{}, nil)
	t.Logf("PHPProcesses: %d findings", len(findings))
}

// testTimeout returns a context that cancels after the given duration.
func testTimeout(d time.Duration) context.Context {
	ctx, _ := context.WithTimeout(context.Background(), d)
	return ctx
}
