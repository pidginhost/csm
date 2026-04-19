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

// Item 3 regression: PHP in /wp-content/languages/ should no longer fire
// Critical purely on path. The content scanner runs first; clean files in
// known-safe sublocations (WPML translation queue, locale .php, .l10n.php)
// produce no alert at all, while clean files in unrecognised sublocations
// of the sensitive dir still get a Warning. Files that trip a real rule
// fire the content-scan Critical and the path alert is suppressed as
// redundant. Coverage for the unknown-clean-PHP Warning lives in
// TestAnalyzeFilePHPInLanguagesAlerts (fanotify_final_linux_test.go).

func TestPHPInLanguagesWPMLQueueCleanContentNoAlert(t *testing.T) {
	dir := t.TempDir()
	queueDir := filepath.Join(dir, "wp-content", "languages", "wpml", "queue")
	if err := os.MkdirAll(queueDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(queueDir, "sitepress.php")
	// Representative WPML translation queue file: returns a PHP array, no
	// webshell patterns, no suspicious URLs, no obfuscation.
	legit := []byte(`<?php
return array(
    'domain' => 'sitepress',
    'entries' => array(
        array( 'singular' => 'Home', 'translation' => 'Acasa' ),
        array( 'singular' => 'About', 'translation' => 'Despre' ),
    ),
);
`)
	if err := os.WriteFile(path, legit, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		t.Errorf("expected no alert for WPML translation queue file, got %+v", got)
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
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

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
