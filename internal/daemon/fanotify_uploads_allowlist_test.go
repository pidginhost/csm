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

// isKnownSafeUploadDaemon used to path-suppress php_in_uploads_realtime for
// any path containing "/sucuri/", "/smush/", "/imunify", "/cache/", etc.
// That's a path allowlist: an attacker only has to create a directory named
// after any listed token and drop the webshell inside.
//
// Post-fix, PHP created in /wp-content/uploads/ is always either a verified
// plugin-update temp directory (Warning via looksLikePluginUpdate) or a
// Critical alert. Operators whitelist legit daemons via the path-scoped
// suppressions_api, which is explicit and auditable.

func TestAnalyzeFile_PHPInUploadsSubdirNamedAfterSafeToken_FiresCritical(t *testing.T) {
	cases := []string{
		"sucuri",
		"smush",
		"imunify",
		"cache",
	}
	for _, token := range cases {
		t.Run(token, func(t *testing.T) {
			dir := t.TempDir()
			uploadsDir := filepath.Join(dir, "wp-content", "uploads", token)
			if err := os.MkdirAll(uploadsDir, 0755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(uploadsDir, "evil.php")
			// 2026-04-27: php_in_uploads_realtime is now content-aware --
			// clean PHP gets Warning, webshell content gets Critical. The
			// "no path allowlist" intent of this test still holds: we drop
			// the file under a formerly-allowlisted token (sucuri/smush/
			// imunify/cache) and verify a Critical fires when the content
			// is malicious. Path-tokens cannot bypass content detection.
			body := "<?php @" + "ev" + "al($_REQUEST['x']); // dropper"
			if err := os.WriteFile(path, []byte(body), 0644); err != nil {
				t.Fatal(err)
			}
			fd := openRawFd(t, path)

			ch := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
			fm.analyzeFile(fileEvent{path: path, fd: fd})

			select {
			case a := <-ch:
				if a.Check != "php_in_uploads_realtime" {
					t.Errorf("Check = %q, want php_in_uploads_realtime", a.Check)
				}
				if a.Severity != alert.Critical {
					t.Errorf("Severity = %v, want Critical (path-based allowlist removed)", a.Severity)
				}
			case <-time.After(200 * time.Millisecond):
				t.Fatalf("expected Critical php_in_uploads_realtime for %s", path)
			}
		})
	}
}


// 2026-04-28: php_in_uploads_realtime now suppresses two structural
// duplicates without skipping content scan:
//   - cPanel restore staging (/home/cpanelpkgrestore.TMP.work.<id>/...).
//     cPanel re-extracts the same files into /home/<account>/ as the user;
//     the user-context fanotify event is the real signal.
//   - WP-Optimize probe files at /wp-content/uploads/wpo/* on sites that
//     actually have the wp-optimize plugin installed and where the file
//     fits the small/no-input/no-exec shape WP-Optimize uses.
//
// In both cases the signature scanner runs first, so a webshell hidden
// behind one of these shapes still trips its own alert. The suppression
// only affects the path-only "anomalous location" warning.

func TestAnalyzeFile_CpanelRestoreStaging_SuppressesAnomalousLocationWarning(t *testing.T) {
	dir := t.TempDir()
	stagingRoot := filepath.Join(dir, "home", "cpanelpkgrestore.TMP.work.79d118fd")
	uploadsDir := filepath.Join(stagingRoot, "unsafe_to_read_archive", "backup-x_user", "homedir",
		"public_html", "wp-content", "uploads", "wpo", "server-signature", "on")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(uploadsDir, "test.php")
	// Reframe the path so it begins with /home/cpanelpkgrestore.TMP.work.<id>:
	// looksLikeCpanelRestoreStaging requires the marker to sit directly
	// under /home, which it cannot do under t.TempDir(). Symlink the
	// staging root so the analysed path matches the production shape.
	if err := os.Symlink(stagingRoot, filepath.Join(dir, "stage")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`<?php header("X: y"); ?>`), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	// Construct an absolute path that begins with /home/... so the
	// recogniser path predicates can match. The file at that path does
	// not exist, but analyzeFile receives the path string from fanotify;
	// it reads content via the fd, not the path.
	productionPath := "/home/cpanelpkgrestore.TMP.work.79d118fd/unsafe_to_read_archive/" +
		"backup-x_user/homedir/public_html/wp-content/uploads/wpo/" +
		"server-signature/on/test.php"

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: productionPath, fd: fd})

	select {
	case a := <-ch:
		t.Errorf("expected no alert for cpanel restore staging duplicate; got %s/%v: %s", a.Check, a.Severity, a.Message)
	case <-time.After(150 * time.Millisecond):
		// expected: no alert
	}
}

func TestAnalyzeFile_WPOptimizeProbe_SuppressesAnomalousLocationWarning(t *testing.T) {
	wpRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-content", "plugins", "wp-optimize"), 0755); err != nil {
		t.Fatal(err)
	}
	uploadsDir := filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "server-signature", "on")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(uploadsDir, "test.php")
	if err := os.WriteFile(path, []byte(`<?php header("Server-Signature: on"); ?>`), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case a := <-ch:
		t.Errorf("expected no alert for WP-Optimize probe file; got %s/%v: %s", a.Check, a.Severity, a.Message)
	case <-time.After(150 * time.Millisecond):
		// expected: no alert
	}
}

func TestAnalyzeFile_WPOptimizeProbe_FallsThroughWhenPluginMissing(t *testing.T) {
	wpRoot := t.TempDir()
	uploadsDir := filepath.Join(wpRoot, "wp-content", "uploads", "wpo")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(uploadsDir, "anything.php")
	if err := os.WriteFile(path, []byte(`<?php header("X: y"); ?>`), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	// No wp-optimize plugin: the recogniser declines, the standard
	// "no webshell markers" warning fires.
	select {
	case a := <-ch:
		if a.Check != "php_in_uploads_realtime" {
			t.Errorf("Check = %q, want php_in_uploads_realtime", a.Check)
		}
		if a.Severity != alert.Warning {
			t.Errorf("Severity = %v, want Warning", a.Severity)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected php_in_uploads_realtime warning when wp-optimize plugin is missing")
	}
}

func TestAnalyzeFile_WPOptimizeProbe_StillFiresOnWebshellContent(t *testing.T) {
	wpRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(wpRoot, "wp-content", "plugins", "wp-optimize"), 0755); err != nil {
		t.Fatal(err)
	}
	uploadsDir := filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "server-signature", "on")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(uploadsDir, "test.php")
	// Drop a real webshell at the WP-Optimize probe location. The shape
	// gate in looksLikeWPOptimizeProbe rejects superglobal use, so the
	// suppression must NOT apply.
	body := "<?php @" + "ev" + "al($_REQUEST['x']);"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case a := <-ch:
		if a.Severity != alert.Critical {
			t.Errorf("Severity = %v, want Critical (webshell content under /uploads/wpo/ must not be suppressed)", a.Severity)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected Critical alert for webshell content under /uploads/wpo/")
	}
}
