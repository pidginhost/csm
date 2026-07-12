//go:build integration

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// newCheckCtx creates a minimal Config + Store for Check* functions on a real
// system. The store is closed on test cleanup.
func newCheckCtx(t *testing.T) (*config.Config, *state.Store) {
	t.Helper()
	cfg := &config.Config{
		StatePath: t.TempDir(),
		Firewall:  &firewall.FirewallConfig{},
	}
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return cfg, store
}

// realCheckTimeout returns a 30s context suitable for real-system scans.
func realCheckTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func assertRealCheckResult(t *testing.T, ctx context.Context, name string, findings []alert.Finding) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		t.Fatalf("%s did not complete within its integration-test budget: %v", name, err)
	}
	for _, finding := range findings {
		if finding.Check == "" {
			t.Fatalf("%s emitted a finding without a check name: %+v", name, finding)
		}
		if finding.Severity < alert.Warning || finding.Severity > alert.Critical {
			t.Fatalf("%s emitted invalid severity: %+v", name, finding)
		}
	}
	t.Logf("%s: %d findings", name, len(findings))
}

// --- filesystem checks ----------------------------------------------------

func TestRealCheckFilesystem(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckFilesystem(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckFilesystem", findings)
}

func TestRealCheckWebshells(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckWebshells(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckWebshells", findings)
}

// --- auth checks ----------------------------------------------------------

func TestRealCheckShadowChanges(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	// First run: establish baseline
	_ = checks.CheckShadowChanges(ctx, cfg, store)
	// Second run: compare against baseline (usually 0 findings)
	findings := checks.CheckShadowChanges(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckShadowChanges (2nd run)", findings)
}

func TestRealCheckSSHKeys(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckSSHKeys(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckSSHKeys", findings)
}

func TestRealCheckAPITokens(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckAPITokens(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckAPITokens", findings)
}

// --- brute force checks ---------------------------------------------------

func TestRealCheckWPBruteForce(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckWPBruteForce(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckWPBruteForce", findings)
}

func TestRealCheckFTPLogins(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckFTPLogins(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckFTPLogins", findings)
}

func TestRealCheckWebmailLogins(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckWebmailLogins(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckWebmailLogins", findings)
}

func TestRealCheckAPIAuthFailures(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckAPIAuthFailures(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckAPIAuthFailures", findings)
}

// --- web checks -----------------------------------------------------------

func TestRealCheckHtaccess(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckHtaccess(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckHtaccess", findings)
}

func TestRealCheckWPCore(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckWPCore(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckWPCore", findings)
}

// --- crontabs / system ----------------------------------------------------

func TestRealCheckCrontabs(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	// Baseline + diff
	_ = checks.CheckCrontabs(ctx, cfg, store)
	findings := checks.CheckCrontabs(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckCrontabs (2nd run)", findings)
}

func TestRealCheckMySQLUsers(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckMySQLUsers(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckMySQLUsers", findings)
}

func TestRealCheckGroupWritablePHP(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckGroupWritablePHP(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckGroupWritablePHP", findings)
}

// --- connections ----------------------------------------------------------

func TestRealCheckSSHDConfig(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	_ = checks.CheckSSHDConfig(ctx, cfg, store)
	findings := checks.CheckSSHDConfig(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckSSHDConfig (2nd run)", findings)
}

func TestRealCheckNulledPlugins(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckNulledPlugins(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckNulledPlugins", findings)
}

// --- exfiltration ---------------------------------------------------------

func TestRealCheckDatabaseDumps(t *testing.T) {
	fakeDump := "/tmp/csm-integ-mysqldump"
	_ = os.Remove(fakeDump)
	if err := os.Symlink("/bin/sleep", fakeDump); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(fakeDump, "30") // #nosec G204 -- fixed integration-test executable and argument.
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.Remove(fakeDump)
	})

	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckDatabaseDumps(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckDatabaseDumps", findings)
	wantPID := strconv.Itoa(cmd.Process.Pid)
	found := false
	for _, finding := range findings {
		if finding.Check == "database_dump" && strings.Contains(finding.Details, "PID: "+wantPID) {
			found = true
		}
	}
	if !found {
		t.Fatalf("database dump process pid %s was not detected: %+v", wantPID, findings)
	}
}

func TestRealCheckOutboundPasteSites(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckOutboundPasteSites(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckOutboundPasteSites", findings)
}

// --- WHM / SSH ------------------------------------------------------------

func TestRealCheckWHMAccess(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckWHMAccess(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckWHMAccess", findings)
}

func TestRealCheckSSHLogins(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckSSHLogins(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckSSHLogins", findings)
}

// --- DNS / SSL ------------------------------------------------------------

func TestRealCheckDNSZoneChanges(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	_ = checks.CheckDNSZoneChanges(ctx, cfg, store)
	findings := checks.CheckDNSZoneChanges(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckDNSZoneChanges (2nd run)", findings)
}

func TestRealCheckSSLCertIssuance(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckSSLCertIssuance(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckSSLCertIssuance", findings)
}

// --- phishing / PHP content ----------------------------------------------

func TestRealCheckPhishing(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckPhishing(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckPhishing", findings)
}

func TestRealCheckPHPContent(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckPHPContent(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckPHPContent", findings)
}

func TestRealCheckPHPConfigChanges(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	_ = checks.CheckPHPConfigChanges(ctx, cfg, store)
	findings := checks.CheckPHPConfigChanges(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckPHPConfigChanges (2nd run)", findings)
}

// --- hardening -----------------------------------------------------------

func TestRealCheckOpenBasedir(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckOpenBasedir(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckOpenBasedir", findings)
}

func TestRealCheckSymlinkAttacks(t *testing.T) {
	linkDir := "/home/csm-integ-symlink-test/public_html"
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "evil-link")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll("/home/csm-integ-symlink-test")
	})

	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckSymlinkAttacks(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckSymlinkAttacks", findings)
	found := false
	for _, finding := range findings {
		if finding.Check == "symlink_attack" && strings.Contains(finding.Message, link) {
			found = true
		}
	}
	if !found {
		t.Fatalf("seeded symlink attack was not detected: %+v", findings)
	}
}

// --- WAF ------------------------------------------------------------------

func TestRealCheckWAFStatus(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckWAFStatus(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckWAFStatus", findings)
}

func TestRealCheckModSecAuditLog(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckModSecAuditLog(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckModSecAuditLog", findings)
}

// --- mail -----------------------------------------------------------------

func TestRealCheckMailQueue(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckMailQueue(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckMailQueue", findings)
}

func TestRealCheckMailPerAccount(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckMailPerAccount(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckMailPerAccount", findings)
}

// --- network / threat -----------------------------------------------------

func TestRealCheckOutboundConnections(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckOutboundConnections(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckOutboundConnections", findings)
}

func TestRealCheckLocalThreatScore(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckLocalThreatScore(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckLocalThreatScore", findings)
}

// --- forwarders (cPanel-specific, tolerant on Ubuntu) --------------------

func TestRealCheckForwarders(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckForwarders(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckForwarders", findings)
}

// --- database content (tolerant — no MySQL on most servers) --------------

func TestRealCheckDatabaseContent(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckDatabaseContent(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckDatabaseContent", findings)
}

// --- email content --------------------------------------------------------

func TestRealCheckOutboundEmailContent(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckOutboundEmailContent(ctx, cfg, store)
	assertRealCheckResult(t, ctx, "CheckOutboundEmailContent", findings)
}
