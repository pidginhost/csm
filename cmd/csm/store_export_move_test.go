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

// Exporting into a directory a customer can write to -- /tmp is the
// obvious one, and /tmp is also on a different filesystem from the
// daemon's state directory, so it always takes the copy path -- used to
// let that customer pre-create the destination as a symlink and have
// root write the whole findings archive through it.
func TestMoveExportedArchiveAcrossFilesystemsDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged.csmbak")
	dst := filepath.Join(dir, "final.csmbak")
	planted := filepath.Join(dir, "planted")
	writeExportFixture(t, src, "archive-bytes")
	if err := os.WriteFile(planted, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(planted, dst); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(planted, dst+".sha256"); err != nil {
		t.Fatal(err)
	}
	forceCrossDeviceRename(t)

	if err := moveExportedArchive(src, dst, sha256Hex("archive-bytes")); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(planted); err != nil || string(data) != "planted" {
		t.Fatalf("symlink target was written through: %q, %v", data, err)
	}
	info, err := os.Lstat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("destination is still a symlink")
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("destination archive mode = %#o, want owner-only", perm)
	}
	if data, err := os.ReadFile(dst); err != nil || string(data) != "archive-bytes" {
		t.Fatalf("destination content = %q, %v", data, err)
	}
	companion, err := os.Lstat(dst + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if companion.Mode()&os.ModeSymlink != 0 {
		t.Fatal("companion is still a symlink")
	}
}

// A copy that cannot be verified must not have already destroyed the
// archive from the previous export sitting at the same path.
func TestMoveExportedArchiveKeepsExistingArchiveOnFailedCopy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged.csmbak")
	dst := filepath.Join(dir, "final.csmbak")
	writeExportFixture(t, src, "archive-bytes")
	if err := os.WriteFile(dst, []byte("previous-export"), 0o600); err != nil {
		t.Fatal(err)
	}
	forceCrossDeviceRename(t)

	if err := moveExportedArchive(src, dst, sha256Hex("other")); err == nil {
		t.Fatal("digest mismatch after copy must fail")
	}
	if data, err := os.ReadFile(dst); err != nil || string(data) != "previous-export" {
		t.Fatalf("previous export destroyed: %q, %v", data, err)
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func forceCrossDeviceRename(t *testing.T) {
	t.Helper()
	old := renameExportFile
	renameExportFile = func(oldPath, newPath string) error {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: syscall.EXDEV}
	}
	t.Cleanup(func() { renameExportFile = old })
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
