//go:build linux

package daemon

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/wpcheck"
)

// TestWPCheckSuppressesWebshellFP verifies that analyzeFile skips the
// knownWebshells check for a verified WP core file named "shell.php".
func TestWPCheckSuppressesWebshellFP(t *testing.T) {
	dir := t.TempDir()

	// Set up fake WP install with shell.php (legitimate WP core file)
	wpRoot := filepath.Join(dir, "home", "user", "public_html")
	diffEngine := filepath.Join(wpRoot, "wp-includes", "Text", "Diff", "Engine")
	if err := os.MkdirAll(diffEngine, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wpRoot, "wp-includes", "version.php"),
		[]byte("<?php\n$wp_version = '6.9.4';\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Write a file named shell.php with known content
	shellContent := []byte("<?php\n// Text_Diff_Engine_shell — legitimate WP core\nclass Text_Diff_Engine_shell {}\n")
	shellPath := filepath.Join(diffEngine, "shell.php")
	if err := os.WriteFile(shellPath, shellContent, 0644); err != nil {
		t.Fatal(err)
	}

	shellHash := md5.Sum(shellContent)
	shellMD5 := hex.EncodeToString(shellHash[:])

	// Set up wpcheck cache with matching checksum
	stateDir := filepath.Join(dir, "state")
	wpCache := wpcheck.NewCache(stateDir)
	checksums := map[string]string{
		"wp-includes/Text/Diff/Engine/shell.php": shellMD5,
	}
	rawJSON, _ := json.Marshal(map[string]interface{}{"checksums": checksums})
	if err := wpCache.PersistChecksums("6.9.4", "en_US", rawJSON, checksums); err != nil {
		t.Fatal(err)
	}

	// Create minimal FileMonitor
	alertCh := make(chan alert.Finding, 10)
	fm := &FileMonitor{
		cfg:     &config.Config{},
		alertCh: alertCh,
		wpCache: wpCache,
	}

	// Open the file to get an fd (simulating fanotify event fd)
	f, err := os.Open(shellPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Call analyzeFile — should NOT produce an alert (WP checksum matches)
	fm.analyzeFile(fileEvent{path: shellPath, fd: int(f.Fd()), pid: 0})

	select {
	case finding := <-alertCh:
		t.Errorf("expected no alert for verified WP core shell.php, got: %s — %s", finding.Check, finding.Message)
	case <-time.After(50 * time.Millisecond):
		// Good — no alert produced
	}
}

// TestWPCheckAllowsModifiedFile verifies that analyzeFile DOES alert
// when a file named shell.php has been modified (MD5 mismatch).
func TestWPCheckAllowsModifiedFile(t *testing.T) {
	dir := t.TempDir()

	wpRoot := filepath.Join(dir, "home", "user", "public_html")
	diffEngine := filepath.Join(wpRoot, "wp-includes", "Text", "Diff", "Engine")
	if err := os.MkdirAll(diffEngine, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wpRoot, "wp-includes", "version.php"),
		[]byte("<?php\n$wp_version = '6.9.4';\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Write a MODIFIED shell.php (injected webshell)
	maliciousContent := []byte("<?php eval($_POST['cmd']); // injected webshell\n")
	shellPath := filepath.Join(diffEngine, "shell.php")
	if err := os.WriteFile(shellPath, maliciousContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Set up wpcheck cache with the LEGITIMATE checksum (won't match)
	stateDir := filepath.Join(dir, "state")
	wpCache := wpcheck.NewCache(stateDir)
	checksums := map[string]string{
		"wp-includes/Text/Diff/Engine/shell.php": "7443bb26aa932003ba7742d0e64007c6", // real WP checksum
	}
	rawJSON, _ := json.Marshal(map[string]interface{}{"checksums": checksums})
	if err := wpCache.PersistChecksums("6.9.4", "en_US", rawJSON, checksums); err != nil {
		t.Fatal(err)
	}

	alertCh := make(chan alert.Finding, 10)
	fm := &FileMonitor{
		cfg:     &config.Config{},
		alertCh: alertCh,
		wpCache: wpCache,
	}

	f, err := os.Open(shellPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Call analyzeFile — SHOULD produce a webshell_realtime alert (MD5 mismatch)
	fm.analyzeFile(fileEvent{path: shellPath, fd: int(f.Fd()), pid: 0})

	select {
	case finding := <-alertCh:
		if finding.Check != "webshell_realtime" {
			t.Errorf("expected webshell_realtime check, got %s", finding.Check)
		}
	case <-time.After(50 * time.Millisecond):
		t.Error("expected webshell_realtime alert for modified shell.php, got none")
	}
}
