package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// The detector only ever looked at /home/*/public_html, so a WordPress install
// serving an addon domain from /home/<user>/<domain>/ was invisible to it. On a
// live host that was 177 of 277 installs -- every one of them still running
// WP-Cron on page loads with no way for the fix to reach them.
func TestWPCronScanCoversAddonDomainDocroots(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")

	// main docroot plus an addon-domain docroot alongside it
	main := filepath.Join(home, "alice", "public_html")
	addon := filepath.Join(home, "alice", "shop.example.com")
	nested := filepath.Join(home, "bob", "blog.example.net", "wp")
	for _, d := range []string{main, addon, nested} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "wp-config.php"),
			[]byte("<?php\n$table_prefix = 'wp_';\nrequire_once ABSPATH . 'wp-settings.php';\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// authoritative cPanel map naming all three docroots
	mapData := strings.Join([]string{
		"example.com: alice==root==main==example.com==" + main + "==192.0.2.10:80==192.0.2.10:443====0==ea-php82",
		"shop.example.com: alice==root==addon==example.com==" + addon + "==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
		"blog.example.net: bob==root==addon==example.net==" + filepath.Dir(nested) + "==192.0.2.11:80==192.0.2.11:443====0==ea-php83",
	}, "\n")

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == userdataDomainsPath {
				return []byte(mapData), nil
			}
			return os.ReadFile(name)
		},
		readDir: os.ReadDir,
		stat:    os.Stat,
		glob:    filepath.Glob,
	})

	cfg := &config.Config{}
	enabled := true
	cfg.Performance.Enabled = &enabled
	cfg.AccountRoots = []string{filepath.Join(home, "*", "public_html")}

	findings := CheckWPCron(context.Background(), cfg, nil)

	// the finding carries the path in Details, not FilePath
	joined := ""
	for _, f := range findings {
		joined += f.Details + "\n" + f.FilePath + "\n"
	}
	for _, want := range []string{
		filepath.Join(main, "wp-config.php"),
		filepath.Join(addon, "wp-config.php"),
		filepath.Join(nested, "wp-config.php"),
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("no perf_wp_cron finding for %s (found %d)", want, len(findings))
		}
	}
}

// A docroot named in the map but owned by nobody, or missing, must not panic or
// produce a finding.
func TestWPCronScanToleratesMissingDocroots(t *testing.T) {
	mapData := "gone.example.com: alice==root==addon==example.com==/nonexistent/docroot==192.0.2.10:80==192.0.2.10:443====0==ea-php82"
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == userdataDomainsPath {
				return []byte(mapData), nil
			}
			return os.ReadFile(name)
		},
		readDir: os.ReadDir,
		stat:    os.Stat,
		glob:    filepath.Glob,
	})
	cfg := &config.Config{}
	enabled := true
	cfg.Performance.Enabled = &enabled
	if f := CheckWPCron(context.Background(), cfg, nil); len(f) != 0 {
		t.Errorf("expected no findings for a missing docroot, got %d", len(f))
	}
}
