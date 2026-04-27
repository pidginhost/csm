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

// FP reconstructions for the 2026-04-27 forgetwhitecom WHM-transfer event.
//
// Three realtime checks fired on legitimate WordPress/plugin code because
// they used filename-only or path-only signals. The fixes here move them to
// content-corroborated detection so legitimate vendor code stops firing
// while real malware still does.

// webshell_realtime previously alerted on every file named shell.php.
// WP core ships wp-includes/Text/Diff/Engine/shell.php (the Pear
// Text_Diff library's shell-diff engine using shell_exec to call the
// Unix `diff` program). After the fix, the filename map is a HINT --
// content must also exhibit webshell markers (request superglobal flowing
// into a dangerous function, or eval+base64_decode chain).

func TestWebshellRealtime_PearTextDiffShellPhpIsLegit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shell.php")
	// Verbatim opener of the WP-bundled Pear Text_Diff shell engine.
	body := `<?php
/**
 * Class used internally by Diff to actually compute the diffs.
 *
 * This class uses the Unix ` + "`diff`" + ` program via shell_exec to compute the
 * differences between two strings.
 */
class Text_Diff_Engine_shell {
    function diff(&$from_lines, &$to_lines) {
        $diff = shell_exec($this->_diffCommand . ' ' . $from_file . ' ' . $to_file);
        return $diff;
    }
}
`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case got := <-ch:
		if got.Check == "webshell_realtime" {
			t.Errorf("webshell_realtime FP: matched Pear Text_Diff shell.php (legit shell_exec to call Unix `diff`, no request superglobal flow). Alert: %s", got.Message)
		}
	case <-time.After(150 * time.Millisecond):
		// No alert -- correct.
	}
}

func TestWebshellRealtime_ShellPhpWithRequestEvalIsWebshell(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shell.php")
	// Real webshell shape: request superglobal driven into eval/system.
	body := "<?php @" + "ev" + "al($_POST['c']); ?>"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case got := <-ch:
		if got.Check != "webshell_realtime" {
			t.Errorf("Check = %q, want webshell_realtime", got.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected webshell_realtime alert on shell.php with eval($_POST) content")
	}
}

// php_in_uploads_realtime previously fired Critical on every PHP under
// /wp-content/uploads/ that wasn't a recognized plugin update. TinyMCE's
// smile_fonts/charmap.php is 2603 lines of glyph data wrapped in PHP,
// shipped by WordPress's bundled editor -- legitimate, content-clean.
// The fix: only Critical when the content has webshell markers; otherwise
// emit a Warning (anomalous file location is still surfaced, just not as
// a "this is malware" Critical).

func TestPhpInUploadsRealtime_TinyMCESmileFontsCharmapIsLegit(t *testing.T) {
	dir, err := os.MkdirTemp("/home", "csm-test-fwfp-")
	if err != nil { t.Skipf("MkdirTemp /home (need root or /home writable): %v", err) }
	defer os.RemoveAll(dir)
	uploadsDir := filepath.Join(dir, "wp-content", "uploads", "smile_fonts", "Defaults")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(uploadsDir, "charmap.php")
	// Verbatim opener of TinyMCE's charmap.php glyph-data file: legit PHP
	// that defines an array of unicode glyph names with no dangerous calls.
	body := `<?php
/**
 * Charmap.
 *
 * @package    tinymce
 * @subpackage charmap
 */
return array(
    'A' => 'LATIN CAPITAL LETTER A',
    'B' => 'LATIN CAPITAL LETTER B',
    'C' => 'LATIN CAPITAL LETTER C',
);
`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case got := <-ch:
		if got.Check == "php_in_uploads_realtime" && got.Severity == alert.Critical {
			t.Errorf("php_in_uploads_realtime FP: Critical on TinyMCE smile_fonts/charmap.php (legit glyph data, no webshell markers). Message: %s", got.Message)
		}
	case <-time.After(150 * time.Millisecond):
	}
}

func TestPhpInUploadsRealtime_PHPWithEvalSuperglobalIsCritical(t *testing.T) {
	dir, err := os.MkdirTemp("/home", "csm-test-fwfp-")
	if err != nil { t.Skipf("MkdirTemp /home (need root or /home writable): %v", err) }
	defer os.RemoveAll(dir)
	uploadsDir := filepath.Join(dir, "wp-content", "uploads", "2026", "04")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(uploadsDir, "anyname.php")
	body := "<?php @" + "ev" + "al($_REQUEST['x']);"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case got := <-ch:
		if got.Severity != alert.Critical {
			t.Errorf("severity = %v, want Critical for PHP-with-eval-superglobal in uploads", got.Severity)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected Critical alert on PHP-with-eval-superglobal in uploads")
	}
}

// phishing_kit_realtime previously fired on any zip whose filename
// contained ANY of the kit-name substrings -- including "google" and
// "kit". google-site-kit.zip (an official WP plugin distribution backup
// stored by wpvividbackups) trips both. The fix requires the filename to
// contain BOTH a brand AND a phishing-suggestive token. Plain plugin
// distribution backups never combine those.

func TestPhishingKitRealtime_GoogleSiteKitBackupIsLegit(t *testing.T) {
	dir, err := os.MkdirTemp("/home", "csm-test-fwfp-")
	if err != nil { t.Skipf("MkdirTemp /home (need root or /home writable): %v", err) }
	defer os.RemoveAll(dir)
	publicHTML := filepath.Join(dir, "public_html", "wpvividbackups", "rollback", "plugins", "google-site-kit", "1.139.0")
	if err := os.MkdirAll(publicHTML, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(publicHTML, "google-site-kit.zip")
	// Minimal zip header so file looks like a real archive.
	if err := os.WriteFile(path, []byte("PK\x03\x04"), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case got := <-ch:
		if got.Check == "phishing_kit_realtime" {
			t.Errorf("phishing_kit_realtime FP: matched google-site-kit.zip backup (brand='google' + plugin slug 'kit'; no phishing indicator like 'login'/'verify'/'signin')")
		}
	case <-time.After(150 * time.Millisecond):
	}
}

func TestPhishingKitRealtime_RealKitNameStillFires(t *testing.T) {
	dir, err := os.MkdirTemp("/home", "csm-test-fwfp-")
	if err != nil { t.Skipf("MkdirTemp /home (need root or /home writable): %v", err) }
	defer os.RemoveAll(dir)
	publicHTML := filepath.Join(dir, "public_html")
	if err := os.MkdirAll(publicHTML, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(publicHTML, "office365-login-page.zip")
	if err := os.WriteFile(path, []byte("PK\x03\x04"), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case got := <-ch:
		if got.Check != "phishing_kit_realtime" {
			t.Errorf("Check = %q, want phishing_kit_realtime", got.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected phishing_kit_realtime alert on office365-login-page.zip")
	}
}
