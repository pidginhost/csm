//go:build linux

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// The verified-CMS skip decides whether signature and YARA scanning run at all.
// Hashing by path let an attacker present clean core content there while the
// bytes the scanner read were malicious, skipping both engines for the file
// actually examined. The hash must come from the descriptor.
func TestHashEventFD_HashesTheOpenFileNotThePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wp-login.php")
	scanned := []byte("<?php // the bytes the scanner read\n")
	if err := os.WriteFile(path, scanned, 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	want := sha256.Sum256(scanned)
	if got := hashEventFD(fd); got != hex.EncodeToString(want[:]) {
		t.Fatalf("hash = %s, want the scanned content's digest", got)
	}

	// The path now resolves to different content.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("<?php // pristine core file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := hashEventFD(fd); got != hex.EncodeToString(want[:]) {
		t.Error("hash followed the path to the replacement instead of the scanned file")
	}
}

// A file larger than the read buffer must hash whole, or a big core file would
// never match its cached digest.
func TestHashEventFD_HashesBeyondOneBuffer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.php")
	content := make([]byte, 200*1024)
	for i := range content {
		content[i] = byte(i % 251)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	want := sha256.Sum256(content)
	if got := hashEventFD(fd); got != hex.EncodeToString(want[:]) {
		t.Errorf("hash = %s, want the whole file's digest", got)
	}
}
