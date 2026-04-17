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
			if err := os.WriteFile(path, []byte("<?php // dropper"), 0644); err != nil {
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
