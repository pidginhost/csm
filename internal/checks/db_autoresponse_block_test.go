package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

// TestBlockSessionAttackerIPs_RoutesThroughRealBlocker asserts that attacker
// IPs pulled from WordPress sessions are handed to the real firewall engine via
// the standard auto-block path, and that the returned finding is the genuine
// AUTO-BLOCK confirmation (not a fabricated one). The previous code emitted a
// fake "auto_block: AUTO-BLOCK: <ip>" finding that never blocked anything, which
// alert.FilterBlockedAlerts then trusted as proof-of-block and used to suppress
// the IP's reputation alert -- so the IP was neither blocked nor alerted.
func TestBlockSessionAttackerIPs_RoutesThroughRealBlocker(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	blocker := &outcomeIPBlocker{outcome: firewall.BlockOutcomeLive}
	swapBlocker(t, blocker)

	actions := blockSessionAttackerIPs(cfg, []string{"203.0.113.7"}, "active session on hijacked site, DB: db1")

	if blocker.outcomeHits != 1 {
		t.Fatalf("expected exactly one real firewall block call, got %d", blocker.outcomeHits)
	}
	if len(blocker.blocked) != 1 || blocker.blocked[0].ip != "203.0.113.7" {
		t.Fatalf("firewall engine did not receive the attacker IP: %+v", blocker.blocked)
	}
	if len(actions) != 1 {
		t.Fatalf("expected one AUTO-BLOCK finding, got %d: %+v", len(actions), actions)
	}
	if actions[0].Check != "auto_block" || !strings.HasPrefix(actions[0].Message, "AUTO-BLOCK:") {
		t.Fatalf("expected a real AUTO-BLOCK finding, got %+v", actions[0])
	}
}

// TestBlockSessionAttackerIPs_DryRunDoesNotFakeBlock guards the CHK-06
// regression: under dry-run the helper must not emit a finding that looks like
// a completed block, or the alert filter would suppress the reputation alert
// for an IP that was never blocked.
func TestBlockSessionAttackerIPs_DryRunDoesNotFakeBlock(t *testing.T) {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	blocker := &outcomeIPBlocker{outcome: firewall.BlockOutcomeDryRun}
	swapBlocker(t, blocker)

	actions := blockSessionAttackerIPs(cfg, []string{"203.0.113.7"}, "active session on hijacked site, DB: db1")

	for _, a := range actions {
		if strings.HasPrefix(a.Message, "AUTO-BLOCK:") && strings.Contains(a.Message, "blocked") {
			t.Fatalf("dry-run must not emit a completed-block finding: %q", a.Message)
		}
	}
}

// TestHandleSiteurlHijack_BlocksAttackerSessionIP is the end-to-end proof that
// a hijack finding drives a real firewall block of the attacker IP found in an
// active WordPress session.
func TestHandleSiteurlHijack_BlocksAttackerSessionIP(t *testing.T) {
	wpConfig := t.TempDir() + "/wp-config.php"
	if err := os.WriteFile(wpConfig, []byte(
		"<?php\n"+
			"define( 'DB_NAME', 'db1' );\n"+
			"define( 'DB_USER', 'u' );\n"+
			"define( 'DB_PASSWORD', 'p' );\n"+
			"define( 'DB_HOST', 'localhost' );\n"+
			"$table_prefix = 'wp_';\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "public_html/wp-config.php") {
				return []string{wpConfig}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if name == wpConfig {
				return os.Open(wpConfig)
			}
			return nil, os.ErrNotExist
		},
	})

	sessionData := `a:1:{s:64:"tok";a:2:{s:2:"ip";s:11:"203.0.113.7";s:5:"login";i:1;}}`
	mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
		switch {
		case strings.Contains(query, "SELECT user_id, meta_value FROM wp_usermeta"):
			return []string{"1\t" + sessionData}, nil
		case strings.Contains(query, "SELECT meta_value FROM wp_usermeta"):
			return []string{sessionData}, nil
		}
		return nil, nil
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })

	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.CleanDatabase = true

	blocker := &outcomeIPBlocker{outcome: firewall.BlockOutcomeLive}
	swapBlocker(t, blocker)

	f := alert.Finding{
		Check:   "db_siteurl_hijack",
		Details: "Database: db1\nsiteurl = http://evil",
	}
	actions := handleSiteurlHijack(cfg, f)

	if blocker.outcomeHits == 0 {
		t.Fatal("attacker session IP was never sent to the firewall engine")
	}
	found := false
	for _, c := range blocker.blocked {
		if c.ip == "203.0.113.7" {
			found = true
		}
	}
	if !found {
		t.Fatalf("firewall engine did not block the attacker IP: %+v", blocker.blocked)
	}
	// No fabricated AUTO-BLOCK finding: any auto_block finding present must be
	// the real one emitted by AutoBlockIPs after a live block.
	for _, a := range actions {
		if a.Check == "auto_block" && strings.Contains(a.Message, "active session on hijacked site") {
			t.Errorf("handleSiteurlHijack still emits a fabricated auto_block finding: %q", a.Message)
		}
	}
}
