package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestRestoreArchive_RejectsPreexistingTargetSymlink verifies that restore
// refuses to follow a symlink that already exists at the archive's target
// path. Without this guard a prior attacker with write access to the
// destination tree could plant a symlink at conf.d/10.yaml pointing at
// /etc/passwd; the next operator-triggered restore would then dutifully
// clobber /etc/passwd with the archive entry's contents.
func TestRestoreArchive_RejectsPreexistingTargetSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behaviour is POSIX-specific")
	}

	src := t.TempDir()
	dst := t.TempDir()
	if err := os.MkdirAll(dst+"/conf.d", 0o700); err != nil {
		t.Fatal(err)
	}
	// Plant the malicious symlink. RestoreBackupArchive must refuse to
	// follow it.
	bait := filepath.Join(dst, "bait.txt")
	if err := os.WriteFile(bait, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bait, filepath.Join(dst, "conf.d", "10.yaml")); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(src, "backup.tar.gz")
	if err := writeArchiveEntry(archive, "conf.d/10.yaml", 9, []byte("OVERWRITE")); err != nil {
		t.Fatal(err)
	}

	err := RestoreBackupArchive(archive, BackupSources{
		ConfigPath: dst + "/csm.yaml",
		ConfDir:    dst + "/conf.d",
		StateDir:   dst + "/state",
	})
	if err == nil {
		t.Fatal("restore must reject symlinked target")
	}

	// The bait must be untouched even after the rejection.
	got, err := os.ReadFile(bait)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "untouched" {
		t.Fatalf("symlink followed; bait clobbered to %q", got)
	}
}

// TestRestoreArchive_RejectsSymlinkInIntermediateDir extends the same
// hardening to a path component above the final target. If an attacker
// can replace a subdirectory under the destination with a symlink, the
// final OpenFile would land outside the controlled tree even with
// O_NOFOLLOW on the leaf.
func TestRestoreArchive_RejectsSymlinkInIntermediateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behaviour is POSIX-specific")
	}

	src := t.TempDir()
	dst := t.TempDir()

	// Attacker-controlled directory outside the destination tree.
	outside := filepath.Join(dst, "..attacker")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	// The intermediate directory inside the destination is a symlink
	// that escapes upward.
	if err := os.Symlink(outside, filepath.Join(dst, "conf.d")); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(src, "backup.tar.gz")
	if err := writeArchiveEntry(archive, "conf.d/10.yaml", 4, []byte("PWND")); err != nil {
		t.Fatal(err)
	}

	err := RestoreBackupArchive(archive, BackupSources{
		ConfigPath: dst + "/csm.yaml",
		ConfDir:    dst + "/conf.d",
		StateDir:   dst + "/state",
	})
	if err == nil {
		t.Fatal("restore must reject symlinked intermediate directory")
	}

	if _, statErr := os.Stat(filepath.Join(outside, "10.yaml")); statErr == nil {
		t.Fatal("symlink escape succeeded; payload landed outside destination")
	}
}

func TestRestoreArchive_RejectsNestedSymlinkInIntermediateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behaviour is POSIX-specific")
	}

	src := t.TempDir()
	dst := t.TempDir()

	outside := filepath.Join(dst, "..attacker")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dst, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dst, "conf.d", "nested")); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(src, "backup.tar.gz")
	if err := writeArchiveEntry(archive, "conf.d/nested/10.yaml", 4, []byte("PWND")); err != nil {
		t.Fatal(err)
	}

	err := RestoreBackupArchive(archive, BackupSources{
		ConfigPath: dst + "/csm.yaml",
		ConfDir:    dst + "/conf.d",
		StateDir:   dst + "/state",
	})
	if err == nil {
		t.Fatal("restore must reject nested symlinked intermediate directory")
	}

	if _, statErr := os.Stat(filepath.Join(outside, "10.yaml")); statErr == nil {
		t.Fatal("nested symlink escape succeeded; payload landed outside destination")
	}
}
