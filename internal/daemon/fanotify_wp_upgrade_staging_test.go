//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// WordPress unpacks every core, plugin and theme update under
// wp-content/upgrade/ before moving it into place. The path-only branch alerted
// once per PHP file, so a single plugin update produced 135 warnings. The
// uploads branch already collapses a verified update to one alert per staging
// directory; these tests hold the upgrade branch to the same contract without
// weakening content detection inside the staging tree.

// cleanStagedPHP is executable plugin code with no webshell markers: not a
// comment-only stub and not a translation cache, so it reaches the path-only
// warning that the collapse governs.
const cleanStagedPHP = `<?php
$settings = array( 'slug' => 'cookie-law-info' );
$settings['modules'] = array( 'banner', 'consent' );
return $settings;
`

func writeStagedFile(t *testing.T, path, body string) int {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return openRawFd(t, path)
}

func drainFindings(ch chan alert.Finding) []alert.Finding {
	var out []alert.Finding
	for {
		select {
		case f := <-ch:
			out = append(out, f)
		case <-time.After(100 * time.Millisecond):
			return out
		}
	}
}

func TestWPUpdateStagingDirShapes(t *testing.T) {
	root := t.TempDir()
	wpRoot := filepath.Join(root, "public_html")
	upgrade := filepath.Join(wpRoot, "wp-content", "upgrade")

	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-content", "plugins", "cookie-law-info"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-content", "themes", "twentytwentyfour"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wpRoot, "wp-includes", "version.php"), []byte("<?php $wp_version='6.4.10';"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "installed plugin package",
			path: filepath.Join(upgrade, "cookie-law-info.3.5.5", "cookie-law-info", "legacy", "loader.php"),
			want: filepath.Join(upgrade, "cookie-law-info.3.5.5"),
		},
		{
			name: "installed theme package",
			path: filepath.Join(upgrade, "twentytwentyfour.1.2", "twentytwentyfour", "functions.php"),
			want: filepath.Join(upgrade, "twentytwentyfour.1.2"),
		},
		{
			name: "core partial package",
			path: filepath.Join(upgrade, "wordpress-6.4.10-partial-8", "wordpress", "wp-login.php"),
			want: filepath.Join(upgrade, "wordpress-6.4.10-partial-8"),
		},
		{
			name: "core full package",
			path: filepath.Join(upgrade, "wordpress-6.4.10", "wordpress", "wp-settings.php"),
			want: filepath.Join(upgrade, "wordpress-6.4.10"),
		},
		{
			name: "package naming nothing installed",
			path: filepath.Join(upgrade, "totally-not-a-plugin.1.0", "totally-not-a-plugin", "shell.php"),
			want: "",
		},
		{
			name: "core-shaped package without a WordPress root",
			path: filepath.Join(root, "elsewhere", "wp-content", "upgrade", "wordpress-6.4.10", "wordpress", "wp-login.php"),
			want: "",
		},
		{
			name: "file directly in upgrade with no package",
			path: filepath.Join(upgrade, "version-current.php"),
			want: "",
		},
		{
			name: "package directory with no unpacked tree",
			path: filepath.Join(upgrade, "cookie-law-info.3.5.5", "loose.php"),
			want: "",
		},
		{
			name: "rollback backup directory is not an update package",
			path: filepath.Join(wpRoot, "wp-content", "upgrade-temp-backup", "plugins", "cookie-law-info", "loader.php"),
			want: "",
		},
		{
			name: "path outside any upgrade directory",
			path: filepath.Join(wpRoot, "wp-content", "plugins", "cookie-law-info", "loader.php"),
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wpPathStatCache.Clear()
			if got := wpUpdateStagingDir(tc.path); got != tc.want {
				t.Errorf("wpUpdateStagingDir(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestPHPInUpgradeVerifiedPluginPackageCollapsesToOneAlert(t *testing.T) {
	wpPathStatCache.Clear()
	wpRoot := filepath.Join(t.TempDir(), "public_html")
	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-content", "plugins", "cookie-law-info"), 0o755); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(wpRoot, "wp-content", "upgrade", "cookie-law-info.3.5.5")

	ch := make(chan alert.Finding, 32)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	for _, rel := range []string{
		filepath.Join("cookie-law-info", "legacy", "loader.php"),
		filepath.Join("cookie-law-info", "legacy", "includes", "class-cookie-law-info.php"),
		filepath.Join("cookie-law-info", "lite", "admin", "class-admin.php"),
	} {
		path := filepath.Join(staging, rel)
		fm.analyzeFile(fileEvent{path: path, fd: writeStagedFile(t, path, cleanStagedPHP)})
	}

	got := drainFindings(ch)
	if len(got) != 1 {
		t.Fatalf("got %d findings for one staged plugin update, want 1: %+v", len(got), got)
	}
	if got[0].Check != "php_in_sensitive_dir_realtime" {
		t.Errorf("Check = %q, want php_in_sensitive_dir_realtime", got[0].Check)
	}
	if got[0].Severity != alert.Warning {
		t.Errorf("Severity = %v, want Warning", got[0].Severity)
	}
	if got[0].FilePath != staging {
		t.Errorf("FilePath = %q, want the staging directory %q", got[0].FilePath, staging)
	}
}

func TestPHPInUpgradeCorePackageCollapsesToOneAlert(t *testing.T) {
	wpPathStatCache.Clear()
	wpRoot := filepath.Join(t.TempDir(), "public_html")
	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wpRoot, "wp-includes", "version.php"), []byte("<?php $wp_version='6.4.10';"), 0o644); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(wpRoot, "wp-content", "upgrade", "wordpress-6.4.10-partial-8")

	ch := make(chan alert.Finding, 32)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	for _, rel := range []string{
		filepath.Join("wordpress", "wp-login.php"),
		filepath.Join("wordpress", "wp-includes", "kses.php"),
		filepath.Join("wordpress", "wp-admin", "includes", "update-core.php"),
	} {
		path := filepath.Join(staging, rel)
		fm.analyzeFile(fileEvent{path: path, fd: writeStagedFile(t, path, cleanStagedPHP)})
	}

	got := drainFindings(ch)
	if len(got) != 1 {
		t.Fatalf("got %d findings for one staged core update, want 1: %+v", len(got), got)
	}
	if got[0].FilePath != staging {
		t.Errorf("FilePath = %q, want the staging directory %q", got[0].FilePath, staging)
	}
}

func TestPHPInUpgradeUnknownPackageAlertsPerFile(t *testing.T) {
	wpPathStatCache.Clear()
	wpRoot := filepath.Join(t.TempDir(), "public_html")
	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-content", "plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(wpRoot, "wp-content", "upgrade", "not-installed.1.0")

	ch := make(chan alert.Finding, 32)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	var paths []string
	for _, rel := range []string{
		filepath.Join("not-installed", "one.php"),
		filepath.Join("not-installed", "two.php"),
	} {
		path := filepath.Join(staging, rel)
		paths = append(paths, path)
		fm.analyzeFile(fileEvent{path: path, fd: writeStagedFile(t, path, cleanStagedPHP)})
	}

	got := drainFindings(ch)
	if len(got) != len(paths) {
		t.Fatalf("got %d findings for a package naming nothing installed, want %d: %+v", len(got), len(paths), got)
	}
	for i, f := range got {
		if f.FilePath != paths[i] {
			t.Errorf("finding %d FilePath = %q, want the file %q", i, f.FilePath, paths[i])
		}
	}
}

func TestPHPInUpgradeTopLevelFileAlertsOnItsOwnPath(t *testing.T) {
	wpPathStatCache.Clear()
	wpRoot := filepath.Join(t.TempDir(), "public_html")
	path := filepath.Join(wpRoot, "wp-content", "upgrade", "version-current.php")

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: writeStagedFile(t, path, cleanStagedPHP)})

	got := drainFindings(ch)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if got[0].FilePath != path {
		t.Errorf("FilePath = %q, want %q", got[0].FilePath, path)
	}
}

// The collapse governs the path-only warning only. Content analysis runs on
// every staged file first, so a backdoor planted inside a staging directory
// that names an installed plugin still reports Critical against its own path.
func TestPHPInUpgradeStagedBackdoorStillCriticalPerFile(t *testing.T) {
	wpPathStatCache.Clear()
	wpRoot := filepath.Join(t.TempDir(), "public_html")
	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-content", "plugins", "cookie-law-info"), 0o755); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(wpRoot, "wp-content", "upgrade", "cookie-law-info.3.5.5")

	ch := make(chan alert.Finding, 32)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}

	clean := filepath.Join(staging, "cookie-law-info", "loader.php")
	fm.analyzeFile(fileEvent{path: clean, fd: writeStagedFile(t, clean, cleanStagedPHP)})

	backdoor := filepath.Join(staging, "cookie-law-info", "legacy", "includes", "class-loader.php")
	fm.analyzeFile(fileEvent{path: backdoor, fd: writeStagedFile(t, backdoor, "<?php system($_GET['cmd']);")})

	var critical *alert.Finding
	for _, f := range drainFindings(ch) {
		if f.Severity == alert.Critical {
			found := f
			critical = &found
		}
	}
	if critical == nil {
		t.Fatal("staged backdoor produced no Critical finding")
	}
	if critical.FilePath != backdoor {
		t.Errorf("Critical FilePath = %q, want the backdoor file %q", critical.FilePath, backdoor)
	}
}
