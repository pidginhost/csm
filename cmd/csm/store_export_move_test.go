package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
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

// A local account that gets to create the destination name first -- /tmp
// is the obvious place, and /tmp is also on a different filesystem from
// the daemon's state directory -- must not be able to point the export
// somewhere it can read. A symlink sitting at the destination is a sign
// of exactly that, so the export is refused rather than quietly replacing
// the link.
func TestMoveExportedArchiveRefusesSymlinkDestination(t *testing.T) {
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
	forceCrossDeviceRename(t)

	err := moveExportedArchive(src, dst, sha256Hex("archive-bytes"))
	if err == nil {
		t.Fatal("export onto a symlink must be refused")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("failed for the wrong reason: %v", err)
	}
	if data, err := os.ReadFile(planted); err != nil || string(data) != "planted" {
		t.Fatalf("symlink target was written through: %q, %v", data, err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("staged archive not kept: %v", err)
	}
}

// Cleaning a path lexically and resolving it the way the kernel does are
// not the same thing: a ".." after a symlink pops the link's target, not
// the directory the link sits in. The check has to look at the directory
// the write actually lands in.
func TestMoveExportedArchiveResolvesParentTraversalThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged.csmbak")
	shared := filepath.Join(dir, "shared")
	sub := filepath.Join(shared, "sub")
	link := filepath.Join(dir, "link")
	// Built by concatenation: filepath.Join would clean the ".." away and
	// the test would no longer describe what an operator can type.
	dst := link + "/../final.csmbak"
	writeExportFixture(t, src, "archive-bytes")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sub, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}

	err := moveExportedArchive(src, dst, sha256Hex("archive-bytes"))
	if err == nil {
		t.Fatal("the directory actually written to must be the one checked")
	}
	if !strings.Contains(err.Error(), "writable by other accounts") {
		t.Fatalf("failed for the wrong reason: %v", err)
	}
	if _, err := os.Stat(filepath.Join(shared, "final.csmbak")); !os.IsNotExist(err) {
		t.Fatal("archive was written into the shared directory anyway")
	}
}

// A symlink on the path carries no permission of its own, so it is judged
// by its owner. One the caller owns is theirs to point wherever they like.
func TestMoveExportedArchiveAllowsOwnSymlinkOnPath(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged.csmbak")
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	dst := filepath.Join(link, "final.csmbak")
	writeExportFixture(t, src, "archive-bytes")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	// A symlink owned by the caller is fine; the walk must still accept it.
	if err := moveExportedArchive(src, dst, sha256Hex("archive-bytes")); err != nil {
		t.Fatalf("export through an own symlink must work: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(real, "final.csmbak")); err != nil || string(data) != "archive-bytes" {
		t.Fatalf("destination content = %q, %v", data, err)
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

	err := moveExportedArchive(src, dst, sha256Hex("other"))
	if err == nil {
		t.Fatal("digest mismatch after copy must fail")
	}
	if !strings.Contains(err.Error(), "does not match export digest") {
		t.Fatalf("failed for the wrong reason: %v", err)
	}
	if data, err := os.ReadFile(dst); err != nil || string(data) != "previous-export" {
		t.Fatalf("previous export destroyed: %q, %v", data, err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("staged archive not kept: %v", err)
	}
	if _, err := os.Stat(src + ".sha256"); err != nil {
		t.Fatalf("staged companion not kept: %v", err)
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

// Verifying the copy proves nothing if another account can rename the
// verified file out of the way before it is moved into place, so a
// destination directory that account can write to is refused outright.
func TestMoveExportedArchiveRefusesSharedDestinationDir(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged.csmbak")
	dstDir := filepath.Join(dir, "shared")
	dst := filepath.Join(dstDir, "final.csmbak")
	writeExportFixture(t, src, "archive-bytes")
	if err := os.Mkdir(dstDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dstDir, 0o777); err != nil {
		t.Fatal(err)
	}

	err := moveExportedArchive(src, dst, sha256Hex("archive-bytes"))
	if err == nil {
		t.Fatal("export into a world-writable directory must be refused")
	}
	if !strings.Contains(err.Error(), "writable by other accounts") {
		t.Fatalf("failed for the wrong reason: %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("archive was written into the shared directory anyway")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("staged archive not kept: %v", err)
	}
}

// Renaming a directory is governed by the permissions of the directory
// holding it, so a private destination directory under a shared parent is
// no protection: that parent's writers can swap the whole directory out.
func TestMoveExportedArchiveRefusesSharedAncestorDir(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged.csmbak")
	outer := filepath.Join(dir, "outer")
	inner := filepath.Join(outer, "inner")
	dst := filepath.Join(inner, "final.csmbak")
	writeExportFixture(t, src, "archive-bytes")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outer, 0o777); err != nil {
		t.Fatal(err)
	}

	err := moveExportedArchive(src, dst, sha256Hex("archive-bytes"))
	if err == nil {
		t.Fatal("export under a world-writable ancestor must be refused")
	}
	if !strings.Contains(err.Error(), "writable by other accounts") {
		t.Fatalf("failed for the wrong reason: %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("archive was written under the shared ancestor anyway")
	}
}

// The sticky bit is what makes /tmp usable: another account can create
// entries there but cannot rename or remove root's.
func TestMoveExportedArchiveAllowsStickyDestinationDir(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged.csmbak")
	dstDir := filepath.Join(dir, "sticky")
	dst := filepath.Join(dstDir, "final.csmbak")
	writeExportFixture(t, src, "archive-bytes")
	if err := os.Mkdir(dstDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dstDir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}

	if err := moveExportedArchive(src, dst, sha256Hex("archive-bytes")); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(dst); err != nil || string(data) != "archive-bytes" {
		t.Fatalf("destination content = %q, %v", data, err)
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
