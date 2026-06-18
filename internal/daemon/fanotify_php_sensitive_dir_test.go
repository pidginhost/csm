//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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
	l10n := []byte("<?php\nreturn ['language'=>'ro','messages'=>['Site flagged.'=>'Site marcat']];\n" +
		strings.Repeat(" ", 70*1024))
	if err := os.WriteFile(path, l10n, 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	head := readFromFd(fd, 65536)
	if len(head) != 65536 {
		t.Fatalf("head read length = %d, want 65536", len(head))
	}
	if isWPTranslationCacheData(fd, head) {
		t.Fatal("partial realtime read of larger file must fail closed")
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
