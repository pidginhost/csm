//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// Item 3 regression: PHP in /wp-content/languages/ should no longer fire
// Critical purely on path. The content scanner runs first; files that trip
// a real rule fire the content-scan Critical, clean real code gets a Warning,
// and content-proven inert stubs stay quiet.

func TestPHPInLanguagesWPMLQueueCleanContentWarns(t *testing.T) {
	dir := t.TempDir()
	queueDir := filepath.Join(dir, "wp-content", "languages", "wpml", "queue")
	if err := os.MkdirAll(queueDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(queueDir, "sitepress.php")
	// Clean but genuinely executable PHP in a sensitive WP dir: builds an array
	// with assignments and returns it, no webshell patterns or obfuscation. A
	// pure data-only "return array(...)" literal is instead recognized as a
	// translation cache and suppressed (see TestPHPInLanguagesTranslationCacheNoAlert);
	// executable code that is not such a literal must still surface as a Warning.
	legit := []byte(`<?php
$queue = array( 'domain' => 'sitepress' );
$queue['entries'] = array(
    array( 'singular' => 'Home', 'translation' => 'Acasa' ),
);
return $queue;
`)
	if err := os.WriteFile(path, legit, 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case got := <-ch:
		if got.Check != "php_in_sensitive_dir_realtime" {
			t.Errorf("Check = %q, want php_in_sensitive_dir_realtime", got.Check)
		}
		if got.Severity != alert.Warning {
			t.Errorf("Severity = %v, want Warning", got.Severity)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("expected Warning for clean PHP in sensitive dir")
	}
}

func TestPHPInLanguagesTranslationCacheNoAlert(t *testing.T) {
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages")
	if err := os.MkdirAll(langDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, "admin-ro_RO.l10n.php")
	// WordPress 6.5+ GlotPress shape: pure data return array with single- and
	// double-quoted strings and a plural entry joined by a "\0" separator.
	l10n := []byte("<?php\nreturn ['language'=>'ro'," +
		"'plural-forms'=>'nplurals=3; plural=(n == 1) ? 0 : 2;'," +
		"'messages'=>['Site flagged.'=>'Site marcat'," +
		"'%s site'=>'%s site' . \"\\0\" . '%s site-uri']];\n")
	if err := os.WriteFile(path, l10n, 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case got := <-ch:
		t.Errorf("expected no alert for WP translation cache, got %+v", got)
	case <-time.After(150 * time.Millisecond):
		// OK
	}
}

func TestPHPInLanguagesLargeTranslationCacheWarns(t *testing.T) {
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages")
	if err := os.MkdirAll(langDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, "admin-ro_RO.l10n.php")
	// Past the whole-file read cap the recognizer never sees the tail, so it
	// must fail closed rather than suppress on a prefix.
	l10n := []byte("<?php\nreturn ['language'=>'ro','messages'=>['Site flagged.'=>'Site marcat']];\n" +
		strings.Repeat(" ", checks.MaxInertPHPScanBytes))
	if err := os.WriteFile(path, l10n, 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	if data := readCompleteFromFd(fd, checks.MaxInertPHPScanBytes); data != nil {
		t.Fatalf("readCompleteFromFd returned %d bytes for an oversize file, want nil", len(data))
	}
	if isWPTranslationCacheData(fd, readFromFd(fd, 65536)) {
		t.Fatal("partial realtime read of a larger file must fail closed")
	}

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case got := <-ch:
		if got.Check != "php_in_sensitive_dir_realtime" {
			t.Errorf("Check = %q, want php_in_sensitive_dir_realtime", got.Check)
		}
		if got.Severity != alert.Warning {
			t.Errorf("Severity = %v, want Warning", got.Severity)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("expected Warning for incomplete realtime translation-cache read")
	}
}

func TestPHPInLanguagesOversizeTerminatedStubNoAlert(t *testing.T) {
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages")
	if err := os.MkdirAll(langDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, "opaque-cache.php")
	body := []byte("<?php __halt_compiler();" + strings.Repeat("x", checks.MaxInertPHPScanBytes))
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)
	if data := readCompleteFromFd(fd, checks.MaxInertPHPScanBytes); data != nil {
		t.Fatalf("oversized stub unexpectedly returned %d complete bytes", len(data))
	}

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case got := <-ch:
		t.Errorf("expected no alert for a proven terminator with an opaque tail, got %+v", got)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestPHPInLanguagesBenignStubNoAlert(t *testing.T) {
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages")
	if err := os.MkdirAll(langDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, "random-name.php")
	if err := os.WriteFile(path, []byte("<?php\n// Silence is golden.\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	select {
	case got := <-ch:
		t.Errorf("expected no alert for content-proven inert stub, got %+v", got)
	case <-time.After(150 * time.Millisecond):
		// OK
	}
}

func TestPHPInLanguagesWebshellFiresCriticalContentScan(t *testing.T) {
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages")
	if err := os.MkdirAll(langDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, "dropped.php")
	// Classic webshell: shell function with request input on the same line.
	webshell := []byte(`<?php system($_GET['c']); ?>`)
	if err := os.WriteFile(path, webshell, 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	// Collect all alerts fired within a short window.
	var got []alert.Finding
	timeout := time.After(250 * time.Millisecond)
	for {
		select {
		case a := <-ch:
			got = append(got, a)
		case <-timeout:
			goto done
		}
	}
done:
	if len(got) == 0 {
		t.Fatal("expected at least one alert for webshell in sensitive dir")
	}

	hasContent := false
	hasSensitiveDirCritical := false
	for _, a := range got {
		if a.Check == "webshell_content_realtime" && a.Severity == alert.Critical {
			hasContent = true
		}
		if a.Check == "php_in_sensitive_dir_realtime" && a.Severity == alert.Critical {
			hasSensitiveDirCritical = true
		}
	}
	if !hasContent {
		t.Errorf("expected Critical webshell_content_realtime from content scan, got: %+v", got)
	}
	if hasSensitiveDirCritical {
		t.Errorf("path-based Critical should be suppressed when content scan already fired, got: %+v", got)
	}
}

// A core update copies the new release's wp-includes/version.php to
// wp-content/upgrade/version-current.php, reads it and deletes it. The copy
// is literal assignments only and cannot run code, so it must not raise the
// clean-content warning on every site that updates.
const wpCoreVersionProbe = `<?php
/**
 * WordPress Version
 *
 * Contains version information for the current WordPress release.
 *
 * @package WordPress
 * @since 1.2.0
 */

/**
 * The WordPress version string.
 *
 * @global string $wp_version
 */
$wp_version = '7.1';

/**
 * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
 *
 * @global int $wp_db_version
 */
$wp_db_version = 60717;

/**
 * Holds the TinyMCE version.
 *
 * @global string $tinymce_version
 */
$tinymce_version = '49110-20250317';

/**
 * Holds the minimum required PHP version.
 *
 * @global string $required_php_version
 */
$required_php_version = '7.4';

/**
 * Holds the names of required PHP extensions.
 *
 * @global string[] $required_php_extensions
 */
$required_php_extensions = array(
	'json',
	'hash',
);

/**
 * Holds the minimum required MySQL version.
 *
 * @global string $required_mysql_version
 */
$required_mysql_version = '5.5.5';
`

func analyzeUpgradeProbe(t *testing.T, body []byte) []alert.Finding {
	t.Helper()
	return analyzeVersionProbeAt(t, "wp-content/upgrade/version-current.php", body)
}

func analyzeVersionProbeAt(t *testing.T, relativePath string, body []byte) []alert.Finding {
	t.Helper()
	path := filepath.Join(t.TempDir(), filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd})

	var got []alert.Finding
	timeout := time.After(150 * time.Millisecond)
	for {
		select {
		case a := <-ch:
			got = append(got, a)
		case <-timeout:
			return got
		}
	}
}

func TestPHPInUpgradeCoreVersionProbeNoAlert(t *testing.T) {
	if got := analyzeUpgradeProbe(t, []byte(wpCoreVersionProbe)); len(got) != 0 {
		t.Errorf("expected no alert for a core update version probe, got %+v", got)
	}
}

func TestPHPInUpgradeVersionShapedCodeWarns(t *testing.T) {
	// Same variables, but one value is computed: that is code, not data.
	body := strings.Replace(wpCoreVersionProbe, "$wp_version = '7.1';", "$wp_version = strtoupper('7.1');", 1)
	got := analyzeUpgradeProbe(t, []byte(body))
	if len(got) != 1 || got[0].Check != "php_in_sensitive_dir_realtime" || got[0].Severity != alert.Warning {
		t.Fatalf("expected one php_in_sensitive_dir_realtime Warning for version-shaped code, got %+v", got)
	}
}

func TestPHPInUpgradeOversizeVersionDataWarns(t *testing.T) {
	// Past the whole-file read cap the tail is never seen, so literal-looking
	// leading assignments cannot prove the file inert.
	body := wpCoreVersionProbe + strings.Repeat(" ", checks.MaxInertPHPScanBytes)
	got := analyzeUpgradeProbe(t, []byte(body))
	if len(got) != 1 || got[0].Check != "php_in_sensitive_dir_realtime" || got[0].Severity != alert.Warning {
		t.Fatalf("expected one php_in_sensitive_dir_realtime Warning for an incomplete read, got %+v", got)
	}
}

func TestPHPInUpgradeVersionDataHidingCodeWarns(t *testing.T) {
	for name, body := range map[string]string{
		"CR slash comment": wpCoreVersionProbe + "// comment\rprint('EXECUTED');",
		"CR hash comment":  wpCoreVersionProbe + "# comment\rprint('EXECUTED');",
		"code past 64 KiB": wpCoreVersionProbe + strings.Repeat(" ", 65536) + "print('EXECUTED');",
	} {
		t.Run(name, func(t *testing.T) {
			got := analyzeUpgradeProbe(t, []byte(body))
			if len(got) != 1 || got[0].Check != "php_in_sensitive_dir_realtime" || got[0].Severity != alert.Warning {
				t.Fatalf("expected one php_in_sensitive_dir_realtime Warning, got %+v", got)
			}
		})
	}
}

// The proof is the content, so the file name neither grants nor withholds it.
func TestPHPInSensitiveDirVersionDataJudgedByContent(t *testing.T) {
	for _, rel := range []string{
		"wp-content/upgrade/version-current.php",
		"wp-content/upgrade/arbitrary.php",
		"wp-content/languages/arbitrary.php",
	} {
		t.Run(rel, func(t *testing.T) {
			if got := analyzeVersionProbeAt(t, rel, []byte(wpCoreVersionProbe)); len(got) != 0 {
				t.Fatalf("expected literal version data to stay quiet, got %+v", got)
			}
			got := analyzeVersionProbeAt(t, rel, []byte(wpCoreVersionProbe+"// comment\rprint('EXECUTED');"))
			if len(got) != 1 || got[0].Check != "php_in_sensitive_dir_realtime" || got[0].Severity != alert.Warning {
				t.Fatalf("expected one php_in_sensitive_dir_realtime Warning, got %+v", got)
			}
		})
	}
}

func TestPHPInSensitiveDirExecutableCommentShapesWarn(t *testing.T) {
	for name, body := range map[string]string{
		"attribute stub":         "<?php #[Example] function example() {} print('EXECUTED');",
		"CR slash before return": "<?php // comment\rprint('EXECUTED');\nreturn [];",
		"CR hash before return":  "<?php # comment\rprint('EXECUTED');\nreturn [];",
	} {
		t.Run(name, func(t *testing.T) {
			got := analyzeVersionProbeAt(t, "wp-content/languages/arbitrary.php", []byte(body))
			if len(got) != 1 || got[0].Check != "php_in_sensitive_dir_realtime" || got[0].Severity != alert.Warning {
				t.Fatalf("expected one php_in_sensitive_dir_realtime Warning, got %+v", got)
			}
		})
	}
}
