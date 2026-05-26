package main

import (
	"bytes"
	"os"
	"path/filepath"
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

func TestPamEnsureLinesHonorsExistingActiveDirective(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd")
	writePAMFile(t, path, "# auth optional pam_csm.so\nauth [success=ok default=ignore] pam_csm.so debug\nsession required pam_unix.so\n")

	changed, err := pamEnsureLines(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("missing session hook should still be added")
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	if strings.Count(body, "auth") != 2 {
		t.Fatalf("existing active auth directive should prevent duplicate auth hook:\n%s", body)
	}
	if !strings.Contains(body, "session  optional   pam_csm.so # managed-by-csm") {
		t.Fatalf("missing managed session hook:\n%s", body)
	}
}

func TestPamEnsureLinesIgnoresCommentedDirective(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd")
	writePAMFile(t, path, "# auth optional pam_csm.so\n")

	changed, err := pamEnsureLines(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("commented pam_csm.so line must not count as hooked")
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	if strings.Count(body, "auth") != 2 {
		t.Fatalf("expected commented auth plus managed auth hook:\n%s", body)
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

func TestPamEnsureLinesAddsNewlineBeforeDirectives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd")
	writePAMFile(t, path, "auth required pam_unix.so")

	changed, err := pamEnsureLines(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected missing directives to be added")
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "pam_unix.soauth") {
		t.Fatalf("directive appended without separator newline:\n%s", got)
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

func TestPamRemoveLinesKeepsOperatorAuthoredDirectives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd")
	body := "#%PAM-1.0\n" +
		"auth optional pam_csm.so debug\n" +
		"session optional pam_csm.so\n" +
		"auth     optional   pam_csm.so # managed-by-csm\n"
	writePAMFile(t, path, body)

	n, err := pamRemoveLines(path)
	if err != nil {
		t.Fatalf("pamRemoveLines: %v", err)
	}
	if n != 1 {
		t.Fatalf("removed = %d, want 1", n)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	out := string(got)
	if !strings.Contains(out, "auth optional pam_csm.so debug") {
		t.Fatalf("operator auth directive was removed:\n%s", out)
	}
	if !strings.Contains(out, "session optional pam_csm.so") {
		t.Fatalf("operator session directive was removed:\n%s", out)
	}
	if strings.Contains(out, pamMarker) {
		t.Fatalf("managed directive still present:\n%s", out)
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
	writePAMFile(t, path, "# auth optional pam_csm.so\n")
	if got := pamFileState(path); got != "not hooked" {
		t.Errorf("pamFileState commented = %q, want not hooked", got)
	}
	if got := pamFileState(filepath.Join(dir, "missing")); got != "absent" {
		t.Errorf("pamFileState absent = %q, want absent", got)
	}
}

func TestCopyFileModeCopiesViaStagingFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.so")
	dst := filepath.Join(dir, "pam_csm.so")
	if err := os.WriteFile(src, []byte("module"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := copyFileMode(src, dst, 0o755); err != nil {
		t.Fatalf("copyFileMode: %v", err)
	}
	got, err := os.ReadFile(dst) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "module" {
		t.Fatalf("copied content = %q, want module", got)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %o, want 755", info.Mode().Perm())
	}
	matches, err := filepath.Glob(filepath.Join(dir, "pam_csm.so.csm-staging-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("staging file left behind: %v", matches)
	}
}

func TestWritePAMBackupDoesNotOverwriteExistingBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd")

	first, err := writePAMBackup(path, []byte("first"))
	if err != nil {
		t.Fatalf("first backup: %v", err)
	}
	second, err := writePAMBackup(path, []byte("second"))
	if err != nil {
		t.Fatalf("second backup: %v", err)
	}
	if first == second {
		t.Fatalf("backup path reused: %s", first)
	}
	firstBody, err := os.ReadFile(first) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	secondBody, err := os.ReadFile(second) // #nosec G304 -- test fixture under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(firstBody) != "first" || string(secondBody) != "second" {
		t.Fatalf("backup contents overwritten: first=%q second=%q", firstBody, secondBody)
	}
}

func TestResolvePAMSecurityDirNotFound(t *testing.T) {
	old := pamSecurityDirs
	pamSecurityDirs = []string{filepath.Join(t.TempDir(), "missing")}
	t.Cleanup(func() { pamSecurityDirs = old })

	if got, err := resolvePAMSecurityDir(); err == nil {
		t.Fatalf("resolvePAMSecurityDir = %q, nil error; want not found", got)
	}
}
