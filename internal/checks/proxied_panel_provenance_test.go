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

// Only the central log names a proxied request by path. A per-site domlog
// whose file name yields no domain is still a per-site log, so a
// client-chosen proxy prefix there counts as website traffic.
func TestDomlogProxyPathCountsWhenTheLogNamesNoDomain(t *testing.T) {
	for _, name := range []string{"localhost-ssl_log", "192.0.2.10"} {
		path := filepath.Join(t.TempDir(), name)
		line := `192.0.2.88 - - [02/Oct/2026:12:00:00 +0000] "POST /___proxy_subdomain_cpanel/wp-login.php HTTP/1.1" 200 10 "-" "Mozilla"` + "\n"
		if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
		if domain := domainFromDomlogPath(path); domain != "" {
			t.Fatalf("fixture %q names domain %q; it must name none", name, domain)
		}
		stats := newDomlogStatsAt(time.Date(2026, 10, 2, 12, 0, 30, 0, time.UTC))
		tailDomlogsInto(context.Background(), []string{path}, &config.Config{}, stats, nopBotClassifier{}, 10)
		if got := stats.wpLogin["192.0.2.88"]; got != 1 {
			t.Errorf("%s: per-site request with a client-chosen proxy path counted %d logins, want 1", name, got)
		}
	}
}

// The periodic scan marks lines from the central access log, so a proxied
// panel request logged there is skipped while direct traffic still counts.
func TestCheckWPBruteForceSkipsCentralProxyPaths(t *testing.T) {
	root := t.TempDir()
	central := filepath.Join(root, "access_log")
	now := time.Now()
	line := func(ip, uri string) string {
		return fmt.Sprintf(`%s - - [%s] "POST %s HTTP/1.1" 401 0 "-" "-"`, ip, now.Format("02/Jan/2006:15:04:05 -0700"), uri)
	}
	var lines []string
	for i := 0; i < 25; i++ {
		lines = append(lines, line("192.0.2.30", "/___proxy_subdomain_cpanel/wp-login.php"), line("192.0.2.31", "/wp-login.php"))
	}
	writeAccessLogLines(t, central, now, lines...)
	const centralPath = "/usr/local/apache/logs/access_log"
	panel := platform.PanelCPanel
	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{
		Panel:          &panel,
		AccessLogPaths: []string{centralPath},
		DomlogGlobs:    []string{filepath.Join(root, "domlogs", "*")},
	})
	t.Cleanup(platform.ResetForTest)
	withMockOS(t, &mockOS{glob: filepath.Glob, stat: func(path string) (os.FileInfo, error) {
		if path == centralPath {
			return os.Stat(central)
		}
		return os.Stat(path)
	}, open: func(path string) (*os.File, error) {
		if path == centralPath {
			return os.Open(central)
		}
		if strings.HasPrefix(path, root+string(filepath.Separator)) {
			return os.Open(path)
		}
		return nil, os.ErrNotExist
	}})

	direct := false
	for _, f := range CheckWPBruteForce(context.Background(), &config.Config{}, nil) {
		if f.Check != "wp_login_bruteforce" {
			continue
		}
		switch f.SourceIP {
		case "192.0.2.30":
			t.Errorf("central proxied panel requests counted: %s", f.Message)
		case "192.0.2.31":
			direct = true
		}
	}
	if !direct {
		t.Fatal("direct central traffic no longer counts")
	}
}

func TestCheckWPBruteForceCountsCustomWebsiteProxyPaths(t *testing.T) {
	for _, panel := range []platform.Panel{platform.PanelNone, platform.PanelCPanel} {
		t.Run(string(panel), func(t *testing.T) {
			root := t.TempDir()
			website := filepath.Join(root, "site.example-ssl_log")
			now := time.Now()
			line := fmt.Sprintf(`192.0.2.30 - - [%s] "POST /___proxy_subdomain_cpanel/wp-login.php HTTP/1.1" 401 0 "-" "-"`, now.Format("02/Jan/2006:15:04:05 -0700"))
			writeAccessLogLines(t, website, now, strings.Split(strings.TrimSpace(strings.Repeat(line+"\n", 25)), "\n")...)
			platform.ResetForTest()
			platform.SetOverrides(platform.Overrides{
				Panel:          &panel,
				AccessLogPaths: []string{website},
				DomlogGlobs:    []string{filepath.Join(root, "*-ssl_log")},
			})
			t.Cleanup(platform.ResetForTest)
			withMockOS(t, &mockOS{glob: filepath.Glob, stat: os.Stat, open: func(path string) (*os.File, error) {
				if strings.HasPrefix(path, root+string(filepath.Separator)) {
					return os.Open(path)
				}
				return nil, os.ErrNotExist
			}})
			got := CheckWPBruteForce(context.Background(), &config.Config{}, nil)
			if len(got) != 1 || got[0].Check != "wp_login_bruteforce" || got[0].SourceIP != "192.0.2.30" {
				t.Fatalf("custom website traffic findings %+v, want one login finding", got)
			}
		})
	}
}
