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

// A hijacked site's session addresses are reported, not blocked, and not
// handed to admission: the firewall, the tracker and the ledger all stay
// untouched, while the sessions are still revoked.
func TestHandleSiteurlHijack_ReportsSessionIPsWithoutBlocking(t *testing.T) {
	const wpConfig = "/home/example-account/public_html/wp-config.php"
	wpConfigFixture := t.TempDir() + "/wp-config.php"
	if err := os.WriteFile(wpConfigFixture, []byte(
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
				return os.Open(wpConfigFixture)
			}
			return nil, os.ErrNotExist
		},
		lstat: func(name string) (os.FileInfo, error) {
			return mockPathInfo(name, []string{wpConfig})
		},
	})

	sessionData := `a:1:{s:64:"tok";a:2:{s:2:"ip";s:11:"203.0.113.7";s:5:"login";i:1;}}`
	revocations := 0
	mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
		switch {
		case strings.HasPrefix(query, "UPDATE wp_usermeta SET meta_value=''") && strings.Contains(query, "user_id=1") && strings.Contains(query, "session_tokens"):
			revocations++
			return nil, nil
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
	a := withAdmission(t)

	f := alert.Finding{
		Check:   "db_siteurl_hijack",
		Details: "Database: db1\nsiteurl = http://evil",
	}
	actions := handleSiteurlHijack(cfg, f, true)

	if blocker.outcomeHits != 0 || len(blocker.blocked) != 0 || len(a.responses()) != 0 || len(a.refused) != 0 {
		t.Fatalf("session addresses were acted on: firewall %+v, admission %+v %v", blocker.blocked, a.responses(), a.refused)
	}
	if len(loadBlockState(cfg.StatePath).IPs) != 0 {
		t.Fatal("a session address entered the block tracker")
	}
	var notice *alert.Finding
	for i := range actions {
		if actions[i].Check == "auto_response" && strings.Contains(actions[i].Details, "203.0.113.7") {
			notice = &actions[i]
		}
		if actions[i].Check == "auto_block" {
			t.Fatalf("an auto_block finding was emitted: %+v", actions[i])
		}
	}
	if notice == nil || notice.Cause == nil || *notice.Cause != alert.CauseOf(f) || revocations != 1 {
		t.Fatalf("actions=%+v revocations=%d, want the caused session notice and one revocation", actions, revocations)
	}
}
