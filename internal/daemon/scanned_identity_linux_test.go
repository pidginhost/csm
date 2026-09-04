//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// The realtime scanner reads content from the event descriptor. Quarantine has
// to be pinned to that object, so the identity must survive the path being
// replaced underneath it -- that swap is the attack this closes.
func TestScannedIdentity_NamesTheOpenFileNotThePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evil.php")
	if err := os.WriteFile(path, []byte("<?php // scanned\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	original := scannedIdentity(fd)
	if original == nil {
		t.Fatal("no identity for an open descriptor")
	}

	// The attacker replaces the file with a different inode.
	if removeErr := os.Remove(path); removeErr != nil {
		t.Fatal(removeErr)
	}
	if writeErr := os.WriteFile(path, []byte("<?php // replacement\n"), 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}

	replaced, statErr := os.Lstat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if os.SameFile(original, replaced) {
		t.Error("identity followed the path to the replacement instead of naming the scanned file")
	}
	if still := scannedIdentity(fd); !os.SameFile(original, still) {
		t.Error("identity of the open descriptor changed")
	}
}
