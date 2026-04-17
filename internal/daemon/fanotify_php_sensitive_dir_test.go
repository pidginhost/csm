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
// Critical purely on path. The content scanner runs first; clean files get
// a Warning ("unexpected PHP in sensitive dir, content clean") while files
// that trip a real rule fire the content-scan Critical and the path alert
// is suppressed as redundant.

func TestPHPInLanguagesWPMLQueueCleanContentWarningNotCritical(t *testing.T) {
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
		if got.Check != "php_in_sensitive_dir_realtime" {
			t.Errorf("Check = %q, want php_in_sensitive_dir_realtime", got.Check)
		}
		if got.Severity != alert.Warning {
			t.Errorf("Severity = %v, want Warning (clean content should not escalate to Critical)", got.Severity)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected a Warning php_in_sensitive_dir_realtime alert for clean content")
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
