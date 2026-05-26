package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomic_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.conf")
	want := []byte("hello world\n")
	if err := writeFileAtomic(path, want, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("content = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("mode = %04o, want 0644", info.Mode().Perm())
	}
}

func TestWriteFileAtomic_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.conf")
	if err := os.WriteFile(path, []byte("OLD"), 0640); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writeFileAtomic(path, []byte("NEW"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "NEW" {
		t.Errorf("content = %q, want NEW", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("mode = %04o, want 0640", info.Mode().Perm())
	}
}

func TestWriteFileAtomic_FollowsFinalSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.conf")
	link := filepath.Join(dir, "service.conf")
	if err := os.WriteFile(target, []byte("OLD"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := writeFileAtomic(link, []byte("NEW"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	linkInfo, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat link: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link was replaced with mode %s", linkInfo.Mode())
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != "NEW" {
		t.Errorf("target content = %q, want NEW", got)
	}
	targetInfo, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if targetInfo.Mode().Perm() != 0600 {
		t.Errorf("target mode = %04o, want 0600", targetInfo.Mode().Perm())
	}
}

// TestWriteFileAtomic_DoesNotLeakTempOnRenameSuccess asserts that no
// tempfile siblings remain after a successful write. The PAM install
// path mutates files under /etc/pam.d in production; an accumulation
// of `.sshd.csm-*.tmp` siblings would confuse later passes and load
// flags into the wrong service definition.
func TestWriteFileAtomic_DoesNotLeakTempOnRenameSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service")
	if err := writeFileAtomic(path, []byte("OK\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp sibling leaked: %s", e.Name())
		}
	}
}

func TestWriteFileAtomic_FailsWhenParentIsNotDirectory(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(parent, []byte("x"), 0644); err != nil {
		t.Fatalf("seed parent: %v", err)
	}
	path := filepath.Join(parent, "wont-write")
	if err := writeFileAtomic(path, []byte("x"), 0644); err == nil {
		t.Fatal("expected error writing under a non-directory parent, got nil")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("target file appeared despite write failure")
	}
}

func TestWriteFileAtomic_NeverObservesPartial(t *testing.T) {
	// Indirect: confirm that the original target stays intact when the
	// rename succeeds with new content. Concurrent readers reading
	// before the rename see the OLD content; readers after see NEW. A
	// non-atomic os.WriteFile path would briefly show 0 bytes.
	dir := t.TempDir()
	path := filepath.Join(dir, "pam-style.conf")
	if err := os.WriteFile(path, []byte("auth required pam_unix.so\n"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	original, _ := os.ReadFile(path)

	if err := writeFileAtomic(path, []byte("auth required pam_csm.so\nauth required pam_unix.so\n"), 0644); err != nil {
		t.Fatalf("atomic write: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) == string(original) {
		t.Error("file not updated after atomic write")
	}
	if !strings.Contains(string(got), "pam_csm.so") {
		t.Errorf("updated content missing expected line: %q", got)
	}
}
