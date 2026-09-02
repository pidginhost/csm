package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The daemon writes the export archive itself, inside its systemd sandbox,
// where the documented /var/backups destination is read-only. The daemon
// now stages the archive under its state directory and the unsandboxed
// CLI moves it to the requested path, copying across filesystems when a
// rename is impossible and verifying the digest after the copy.
func TestMoveExportedArchiveRenamesOnSameFilesystem(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged.csmbak")
	dst := filepath.Join(dir, "out", "final.csmbak")
	writeExportFixture(t, src, "archive-bytes")

	if err := moveExportedArchive(src, dst, sha256Hex("archive-bytes")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("staged archive still present after move")
	}
	if _, err := os.Stat(src + ".sha256"); !os.IsNotExist(err) {
		t.Fatal("staged companion still present after move")
	}
	if data, err := os.ReadFile(dst); err != nil || string(data) != "archive-bytes" {
		t.Fatalf("destination content = %q, %v", data, err)
	}
	if _, err := os.Stat(dst + ".sha256"); err != nil {
		t.Fatalf("companion file not moved: %v", err)
	}
}

func TestMoveExportedArchiveCopiesAcrossFilesystems(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged.csmbak")
	dst := filepath.Join(dir, "final.csmbak")
	writeExportFixture(t, src, "archive-bytes")

	old := renameExportFile
	renameExportFile = func(string, string) error { return &os.LinkError{Op: "rename", Old: src, New: dst, Err: syscall.EXDEV} }
	t.Cleanup(func() { renameExportFile = old })

	if err := moveExportedArchive(src, dst, sha256Hex("archive-bytes")); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(dst); err != nil || string(data) != "archive-bytes" {
		t.Fatalf("destination content = %q, %v", data, err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("staged archive not removed after copy")
	}
}

func TestMoveExportedArchiveRejectsDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged.csmbak")
	dst := filepath.Join(dir, "final.csmbak")
	writeExportFixture(t, src, "archive-bytes")

	old := renameExportFile
	renameExportFile = func(string, string) error { return &os.LinkError{Op: "rename", Old: src, New: dst, Err: syscall.EXDEV} }
	t.Cleanup(func() { renameExportFile = old })

	if err := moveExportedArchive(src, dst, sha256Hex("other")); err == nil {
		t.Fatal("digest mismatch after copy must fail")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatal("staged archive must be kept when the copy cannot be verified")
	}
}

// The export archive holds every finding CSM has recorded. Creating the
// destination directory world-readable would leave that directory listing
// open to every local account on a shared host, so the CLI creates it
// private to root and its group.
func TestMoveExportedArchiveCreatesPrivateDestinationDir(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged.csmbak")
	dstDir := filepath.Join(dir, "exports")
	dst := filepath.Join(dstDir, "final.csmbak")
	writeExportFixture(t, src, "archive-bytes")

	if err := moveExportedArchive(src, dst, sha256Hex("archive-bytes")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dstDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		t.Fatalf("destination directory mode = %#o, want no world access", perm)
	}
}

func writeExportFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sha256", []byte(sha256Hex(content)+"  "+filepath.Base(path)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
