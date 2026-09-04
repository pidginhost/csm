package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func withQuarantineDirIdentity(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := quarantineDir
	quarantineDir = dir
	t.Cleanup(func() { quarantineDir = old })
	return dir
}

// The realtime scanner reads content from the fanotify event descriptor, then
// quarantine re-identified the file by path. An attacker who replaces the file
// in that window gets CSM to move the replacement while the malware it actually
// scanned survives under another name.
func TestInlineQuarantine_RefusesFileReplacedAfterScan(t *testing.T) {
	withQuarantineDirIdentity(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "evil.php")
	payload := []byte(generateHighEntropyPHP(8000))
	writeTestFile(t, target, payload)

	// Identity of the file the scanner actually read.
	scanned, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("stat scanned file: %v", err)
	}

	// The attacker swaps in a different inode after detection.
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, target, []byte("<?php // an ordinary file\n"))

	f := alert.Finding{
		Severity: alert.Critical,
		Check:    "signature_match_realtime",
		Details:  "Category: dropper\nDescription: PHP goto obfuscation\nMatched: goto",
		FilePath: target,
	}
	if qPath, ok := InlineQuarantineIdentified(f, target, payload, scanned); ok {
		t.Fatalf("quarantined the replacement instead of refusing: %s", qPath)
	}
	if _, err := os.Lstat(target); err != nil {
		t.Errorf("the replacement was moved anyway: %v", err)
	}
}

// The ordinary case still quarantines: identity matches what was scanned.
func TestInlineQuarantine_MovesTheScannedFile(t *testing.T) {
	qdir := withQuarantineDirIdentity(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "evil.php")
	payload := []byte(generateHighEntropyPHP(8000))
	writeTestFile(t, target, payload)

	scanned, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("stat scanned file: %v", err)
	}

	f := alert.Finding{
		Severity: alert.Critical,
		Check:    "signature_match_realtime",
		Details:  "Category: dropper\nDescription: PHP goto obfuscation\nMatched: goto",
		FilePath: target,
	}
	qPath, ok := InlineQuarantineIdentified(f, target, payload, scanned)
	if !ok {
		t.Fatal("a file matching what was scanned must still be quarantined")
	}
	if filepath.Dir(qPath) != qdir {
		t.Errorf("quarantined outside the quarantine directory: %s", qPath)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Errorf("original still present after quarantine: %v", err)
	}
}
