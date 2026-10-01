package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestCheckWPBruteForceCountsCentralAliasesOnce(t *testing.T) {
	root := t.TempDir()
	central := filepath.Join(root, "central.log")
	aliasA := filepath.Join(root, "apache_access_log")
	aliasB := filepath.Join(root, "easyapache_access_log")
	vhost := filepath.Join(root, "example.test_log")
	now := time.Now()
	line := func(ip string) string {
		return fmt.Sprintf(`%s - - [%s] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`, ip, now.Format("02/Jan/2006:15:04:05 -0700"))
	}
	writeAccessLogLines(t, central, now, strings.Split(strings.TrimSpace(strings.Repeat(line("192.0.2.10")+"\n", 12)), "\n")...)
	writeAccessLogLines(t, vhost, now, strings.Split(strings.TrimSpace(strings.Repeat(line("192.0.2.20")+"\n", 22)), "\n")...)
	for _, alias := range []string{aliasA, aliasB} {
		if err := os.Symlink(central, alias); err != nil {
			t.Fatal(err)
		}
	}

	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{
		AccessLogPaths: []string{filepath.Join(root, "missing.log"), aliasA, aliasB, vhost},
		DomlogGlobs:    []string{filepath.Join(root, "*_log")},
	})
	t.Cleanup(platform.ResetForTest)
	withMockOS(t, &mockOS{glob: filepath.Glob, stat: os.Stat, open: func(path string) (*os.File, error) {
		if strings.HasPrefix(path, root+string(filepath.Separator)) {
			return os.Open(path)
		}
		return nil, os.ErrNotExist
	}})

	findings := CheckWPBruteForce(context.Background(), &config.Config{}, nil)
	foundVhost := false
	for _, f := range findings {
		if f.Check != "wp_login_bruteforce" {
			continue
		}
		if f.SourceIP == "192.0.2.10" {
			t.Errorf("central log aliases inflated the request count: %s", f.Message)
		}
		if f.SourceIP == "192.0.2.20" {
			foundVhost = true
		}
	}
	if !foundVhost {
		t.Fatal("unselected candidate matching the domlog glob was lost")
	}
}

func TestCPanelWebChecksUseApacheFallbacks(t *testing.T) {
	for _, path := range []string{"/var/log/apache2/access_log", "/etc/apache2/logs/access_log"} {
		t.Run(path, func(t *testing.T) {
			panel, server := platform.PanelCPanel, platform.WSApache
			platform.ResetForTest()
			platform.SetOverrides(platform.Overrides{Panel: &panel, WebServer: &server})
			t.Cleanup(platform.ResetForTest)
			now := time.Now().Format("02/Jan/2006:15:04:05 -0700")
			webLine := fmt.Sprintf(`192.0.2.10 - - [%s] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`, now)
			panelLine := fmt.Sprintf(`192.0.2.20 - - [%s] "POST /cpsess123/3rdparty/phpMyAdmin/index.php HTTP/1.1" 200 0 "-" "-"`, now)
			withMockOS(t, writeMockLogs(t, map[string]string{
				path:                                strings.Repeat(webLine+"\n", 25),
				"/usr/local/cpanel/logs/access_log": panelLine + "\n",
			}))

			findings := CheckWPBruteForce(context.Background(), &config.Config{}, nil)
			if len(findings) != 1 || findings[0].Check != "wp_login_bruteforce" || findings[0].SourceIP != "192.0.2.10" {
				t.Fatalf("Apache fallback traffic was lost behind the panel log: %v", findings)
			}
			ips := collectRecentIPs(&config.Config{})
			if len(ips) != 2 || ips["192.0.2.10"] != "HTTP request" || ips["192.0.2.20"] != "cPanel/WHM access" {
				t.Fatalf("web and panel reputation sources = %v", ips)
			}
		})
	}
}
