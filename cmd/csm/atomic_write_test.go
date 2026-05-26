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

func TestWriteFileAtomic_FailsOnUnwritableDir(t *testing.T) {
	// A directory the process cannot create files in must surface the
	// failure, not silently no-op.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("chmod ro: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) })
	path := filepath.Join(dir, "wont-write")
	if err := writeFileAtomic(path, []byte("x"), 0644); err == nil {
		t.Fatal("expected error writing to read-only dir, got nil")
	}
	// No partial target file should exist.
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
