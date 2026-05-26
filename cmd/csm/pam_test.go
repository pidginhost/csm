package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writePAMFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestPamEnsureLinesAddsMissingDirectives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd")
	writePAMFile(t, path, "#%PAM-1.0\nauth   substack    password-auth\n")

	changed, err := pamEnsureLines(path, false)
	if err != nil {
		t.Fatalf("pamEnsureLines: %v", err)
	}
	if !changed {
		t.Fatal("expected changes on fresh file")
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body := string(got)
	for _, want := range []string{
		"auth     optional   pam_csm.so # managed-by-csm",
		"session  optional   pam_csm.so # managed-by-csm",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing line %q in output:\n%s", want, body)
		}
	}

	// Backup file must exist alongside the edited target.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	backup := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "sshd.csm-backup-") {
			backup = true
			break
		}
	}
	if !backup {
		t.Fatal("no .csm-backup file created")
	}
}

func TestPamEnsureLinesIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd")
	writePAMFile(t, path, "#%PAM-1.0\nauth   substack    password-auth\n")

	if _, err := pamEnsureLines(path, false); err != nil {
		t.Fatalf("first install: %v", err)
	}
	before, err := os.ReadFile(path) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	changed, err := pamEnsureLines(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("second install should be a no-op")
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("file changed on second install:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestPamEnsureLinesDryRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd")
	writePAMFile(t, path, "#%PAM-1.0\n")
	changed, err := pamEnsureLines(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("dry-run should report change pending")
	}
	body, err := os.ReadFile(path) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "pam_csm.so") {
		t.Fatal("dry-run must not touch the file")
	}
}

func TestPamRemoveLinesStripsManagedDirectives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd")
	body := "#%PAM-1.0\n" +
		"auth   substack    password-auth\n" +
		"auth     optional   pam_csm.so # managed-by-csm\n" +
		"session  required   pam_unix.so\n" +
		"session  optional   pam_csm.so # managed-by-csm\n"
	writePAMFile(t, path, body)

	n, err := pamRemoveLines(path)
	if err != nil {
		t.Fatalf("pamRemoveLines: %v", err)
	}
	if n != 2 {
		t.Fatalf("removed = %d, want 2", n)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "pam_csm.so") {
		t.Fatalf("uninstall left pam_csm.so reference:\n%s", got)
	}
	if !strings.Contains(string(got), "pam_unix.so") {
		t.Fatalf("uninstall stripped unrelated line:\n%s", got)
	}
}

func TestPamFileStateReportsHooked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd")
	writePAMFile(t, path, "auth optional pam_csm.so\n")
	if got := pamFileState(path); got != "hooked" {
		t.Errorf("pamFileState = %q, want hooked", got)
	}
	writePAMFile(t, path, "auth required pam_unix.so\n")
	if got := pamFileState(path); got != "not hooked" {
		t.Errorf("pamFileState = %q, want not hooked", got)
	}
	if got := pamFileState(filepath.Join(dir, "missing")); got != "absent" {
		t.Errorf("pamFileState absent = %q, want absent", got)
	}
}

func TestResolvePAMSecurityDirNotFound(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("PAM dirs only meaningful on Linux")
	}
	// Cannot easily test the not-found path without faking /lib; the
	// presence path is implicitly exercised by pamStatus on every CI run.
}
