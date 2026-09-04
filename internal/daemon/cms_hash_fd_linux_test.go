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
	if got := hashEventFD(fd, nil, int64(len(scanned))); got != hex.EncodeToString(want[:]) {
		t.Fatalf("hash = %s, want the scanned content's digest", got)
	}

	// The path now resolves to different content.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("<?php // pristine core file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := hashEventFD(fd, nil, int64(len(scanned))); got != hex.EncodeToString(want[:]) {
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
	if got := hashEventFD(fd, nil, int64(len(content))); got != hex.EncodeToString(want[:]) {
		t.Errorf("hash = %s, want the whole file's digest", got)
	}
}

func TestHashEventFD_LeavesDescriptorOffsetUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "offset.php")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if _, err := unix.Seek(fd, 5, 0); err != nil {
		t.Fatal(err)
	}
	if got := hashEventFD(fd, nil, 10); got == "" {
		t.Fatal("hash failed")
	}
	offset, err := unix.Seek(fd, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 5 {
		t.Fatalf("descriptor offset = %d, want 5", offset)
	}
}

func TestHashEventFD_InvalidDescriptorFails(t *testing.T) {
	if got := hashEventFD(-1, nil, 0); got != "" {
		t.Fatalf("invalid descriptor hash = %q, want empty", got)
	}
}

func TestHashEventFD_PreservesAlreadyScannedPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "in-place.php")
	malicious := []byte("EVIL-prefix-clean-tail")
	clean := []byte("clean-prefix-clean-tail")
	if len(malicious) != len(clean) {
		t.Fatal("test contents must have the same size")
	}
	if err := os.WriteFile(path, malicious, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	prefix := append([]byte(nil), malicious[:len("EVIL-prefix")]...)

	// Replacing bytes through the same inode must not make the hash forget what
	// the scanner already consumed.
	if err := os.WriteFile(path, clean, 0o600); err != nil {
		t.Fatal(err)
	}
	mixed := append(append([]byte(nil), prefix...), clean[len(prefix):]...)
	want := sha256.Sum256(mixed)
	if got := hashEventFD(fd, prefix, int64(len(clean))); got != hex.EncodeToString(want[:]) {
		t.Fatalf("hash = %q, want the scanned prefix followed by the current tail", got)
	}
}

func TestHashEventFD_RejectsFilesOutsideExpectedSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "growing.php")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	if got := hashEventFD(fd, nil, 9); got != "" {
		t.Fatalf("hash with stale size = %q, want empty", got)
	}
}
