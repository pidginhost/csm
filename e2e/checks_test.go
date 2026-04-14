//go:build integration

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// --- filesystem checks ----------------------------------------------------

func TestRealCheckFilesystem(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckFilesystem(ctx, cfg, store)
	t.Logf("CheckFilesystem: %d findings", len(findings))
}

func TestRealCheckWebshells(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckWebshells(ctx, cfg, store)
	t.Logf("CheckWebshells: %d findings", len(findings))
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
	t.Logf("CheckShadowChanges (2nd run): %d findings", len(findings))
}

func TestRealCheckSSHKeys(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckSSHKeys(ctx, cfg, store)
	t.Logf("CheckSSHKeys: %d findings", len(findings))
}

func TestRealCheckAPITokens(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckAPITokens(ctx, cfg, store)
	t.Logf("CheckAPITokens: %d findings", len(findings))
}

// --- brute force checks ---------------------------------------------------

func TestRealCheckWPBruteForce(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckWPBruteForce(ctx, cfg, store)
	t.Logf("CheckWPBruteForce: %d findings", len(findings))
}

func TestRealCheckFTPLogins(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckFTPLogins(ctx, cfg, store)
	t.Logf("CheckFTPLogins: %d findings", len(findings))
}

func TestRealCheckWebmailLogins(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckWebmailLogins(ctx, cfg, store)
	t.Logf("CheckWebmailLogins: %d findings", len(findings))
}

func TestRealCheckAPIAuthFailures(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckAPIAuthFailures(ctx, cfg, store)
	t.Logf("CheckAPIAuthFailures: %d findings", len(findings))
}

// --- web checks -----------------------------------------------------------

func TestRealCheckHtaccess(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckHtaccess(ctx, cfg, store)
	t.Logf("CheckHtaccess: %d findings", len(findings))
}

func TestRealCheckWPCore(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckWPCore(ctx, cfg, store)
	t.Logf("CheckWPCore: %d findings", len(findings))
}

// --- crontabs / system ----------------------------------------------------

func TestRealCheckCrontabs(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	// Baseline + diff
	_ = checks.CheckCrontabs(ctx, cfg, store)
	findings := checks.CheckCrontabs(ctx, cfg, store)
	t.Logf("CheckCrontabs (2nd run): %d findings", len(findings))
}

func TestRealCheckMySQLUsers(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckMySQLUsers(ctx, cfg, store)
	t.Logf("CheckMySQLUsers: %d findings", len(findings))
}

func TestRealCheckGroupWritablePHP(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckGroupWritablePHP(ctx, cfg, store)
	t.Logf("CheckGroupWritablePHP: %d findings", len(findings))
}

// --- connections ----------------------------------------------------------

func TestRealCheckSSHDConfig(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	_ = checks.CheckSSHDConfig(ctx, cfg, store)
	findings := checks.CheckSSHDConfig(ctx, cfg, store)
	t.Logf("CheckSSHDConfig (2nd run): %d findings", len(findings))
}

func TestRealCheckNulledPlugins(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckNulledPlugins(ctx, cfg, store)
	t.Logf("CheckNulledPlugins: %d findings", len(findings))
}

// --- exfiltration ---------------------------------------------------------

func TestRealCheckDatabaseDumps(t *testing.T) {
	// Seed a realistic dump file in /tmp so the scanner has something to find.
	tmpFile := "/tmp/csm-integ-dump-test.sql"
	content := "-- MySQL dump 10.13  Distrib 8.0\n-- Host: localhost    Database: wp_test\n"
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err == nil {
		t.Cleanup(func() { _ = os.Remove(tmpFile) })
	}

	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckDatabaseDumps(ctx, cfg, store)
	t.Logf("CheckDatabaseDumps: %d findings", len(findings))
}

func TestRealCheckOutboundPasteSites(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckOutboundPasteSites(ctx, cfg, store)
	t.Logf("CheckOutboundPasteSites: %d findings", len(findings))
}

// --- WHM / SSH ------------------------------------------------------------

func TestRealCheckWHMAccess(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckWHMAccess(ctx, cfg, store)
	t.Logf("CheckWHMAccess: %d findings", len(findings))
}

func TestRealCheckSSHLogins(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckSSHLogins(ctx, cfg, store)
	t.Logf("CheckSSHLogins: %d findings", len(findings))
}

// --- DNS / SSL ------------------------------------------------------------

func TestRealCheckDNSZoneChanges(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	_ = checks.CheckDNSZoneChanges(ctx, cfg, store)
	findings := checks.CheckDNSZoneChanges(ctx, cfg, store)
	t.Logf("CheckDNSZoneChanges (2nd run): %d findings", len(findings))
}

func TestRealCheckSSLCertIssuance(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckSSLCertIssuance(ctx, cfg, store)
	t.Logf("CheckSSLCertIssuance: %d findings", len(findings))
}

// --- phishing / PHP content ----------------------------------------------

func TestRealCheckPhishing(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckPhishing(ctx, cfg, store)
	t.Logf("CheckPhishing: %d findings", len(findings))
}

func TestRealCheckPHPContent(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckPHPContent(ctx, cfg, store)
	t.Logf("CheckPHPContent: %d findings", len(findings))
}

func TestRealCheckPHPConfigChanges(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	_ = checks.CheckPHPConfigChanges(ctx, cfg, store)
	findings := checks.CheckPHPConfigChanges(ctx, cfg, store)
	t.Logf("CheckPHPConfigChanges (2nd run): %d findings", len(findings))
}

// --- hardening -----------------------------------------------------------

func TestRealCheckOpenBasedir(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckOpenBasedir(ctx, cfg, store)
	t.Logf("CheckOpenBasedir: %d findings", len(findings))
}

func TestRealCheckSymlinkAttacks(t *testing.T) {
	// Seed a test symlink so the scanner has something to look at.
	linkDir := filepath.Join(os.TempDir(), "csm-integ-symlink-test")
	_ = os.MkdirAll(linkDir, 0755)
	link := filepath.Join(linkDir, "evil-link")
	_ = os.Symlink("/etc/passwd", link)
	t.Cleanup(func() {
		_ = os.Remove(link)
		_ = os.Remove(linkDir)
	})

	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckSymlinkAttacks(ctx, cfg, store)
	t.Logf("CheckSymlinkAttacks: %d findings", len(findings))
}

// --- WAF ------------------------------------------------------------------

func TestRealCheckWAFStatus(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckWAFStatus(ctx, cfg, store)
	t.Logf("CheckWAFStatus: %d findings", len(findings))
}

func TestRealCheckModSecAuditLog(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckModSecAuditLog(ctx, cfg, store)
	t.Logf("CheckModSecAuditLog: %d findings", len(findings))
}

// --- mail -----------------------------------------------------------------

func TestRealCheckMailQueue(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckMailQueue(ctx, cfg, store)
	t.Logf("CheckMailQueue: %d findings", len(findings))
}

func TestRealCheckMailPerAccount(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckMailPerAccount(ctx, cfg, store)
	t.Logf("CheckMailPerAccount: %d findings", len(findings))
}

// --- network / threat -----------------------------------------------------

func TestRealCheckOutboundConnections(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckOutboundConnections(ctx, cfg, store)
	t.Logf("CheckOutboundConnections: %d findings", len(findings))
}

func TestRealCheckLocalThreatScore(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckLocalThreatScore(ctx, cfg, store)
	t.Logf("CheckLocalThreatScore: %d findings", len(findings))
}

// --- forwarders (cPanel-specific, tolerant on Ubuntu) --------------------

func TestRealCheckForwarders(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckForwarders(ctx, cfg, store)
	t.Logf("CheckForwarders: %d findings", len(findings))
}

// --- database content (tolerant — no MySQL on most servers) --------------

func TestRealCheckDatabaseContent(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckDatabaseContent(ctx, cfg, store)
	t.Logf("CheckDatabaseContent: %d findings", len(findings))
}

// --- email content --------------------------------------------------------

func TestRealCheckOutboundEmailContent(t *testing.T) {
	cfg, store := newCheckCtx(t)
	ctx, cancel := realCheckTimeout()
	defer cancel()
	findings := checks.CheckOutboundEmailContent(ctx, cfg, store)
	t.Logf("CheckOutboundEmailContent: %d findings", len(findings))
}
