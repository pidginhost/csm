package checks

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func inodeOf(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Ino)
	}
	return 0
}

// realTempDir returns a t.TempDir() canonicalized through EvalSymlinks
// so the path stays stable across the symlink that macOS keeps between
// /var/folders and /private/var/folders. resolveExistingFixPath evaluates
// symlinks and re-checks the result against fixPerfAllowedRoots; without
// this canonicalization the test path looks "outside" its own root.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return resolved
}

// withPerfFixRoots redirects fixPerfAllowedRoots at root for the
// duration of a test so writes land under t.TempDir() instead of
// /home. Mirrors the pattern used by remediate_test.go for the other
// fix actions.
func withPerfFixRoots(t *testing.T, root string) {
	t.Helper()
	prev := fixPerfAllowedRoots
	fixPerfAllowedRoots = []string{root}
	t.Cleanup(func() { fixPerfAllowedRoots = prev })
}

func TestFixErrorLogBloatTruncatesInPlace(t *testing.T) {
	root := realTempDir(t)
	withPerfFixRoots(t, root)
	acct := filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(acct, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(acct, "error_log")
	if err := os.WriteFile(log, []byte(strings.Repeat("oops\n", 4096)), 0o644); err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(log)
	inoBefore := fileInode(t, log)

	res := FixErrorLogBloat(log)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	info, err := os.Stat(log)
	if err != nil {
		t.Fatalf("file removed: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("size after truncate = %d, want 0", info.Size())
	}
	if info.Mode().Perm() != stat.Mode().Perm() {
		t.Errorf("perm changed: was %o, now %o", stat.Mode().Perm(), info.Mode().Perm())
	}
	if got := fileInode(t, log); got != inoBefore {
		t.Errorf("inode changed: was %d, now %d (truncate must preserve inode)", inoBefore, got)
	}
}

func TestFixErrorLogBloatRefusesNonErrorLogName(t *testing.T) {
	root := realTempDir(t)
	withPerfFixRoots(t, root)
	acct := filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(acct, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(acct, "wp-config.php")
	if err := os.WriteFile(path, []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := FixErrorLogBloat(path)
	if res.Success {
		t.Fatal("expected refusal for non error_log file")
	}
	if !strings.Contains(res.Error, "non error_log") {
		t.Errorf("error message = %q, want refusal reason", res.Error)
	}
}

func TestFixErrorLogBloatRejectsPathOutsideRoot(t *testing.T) {
	root := realTempDir(t)
	withPerfFixRoots(t, root)
	res := FixErrorLogBloat("/etc/error_log")
	if res.Success {
		t.Fatal("expected refusal for path outside allowed roots")
	}
}

func TestFixDisplayErrorsOnRewritesUserIni(t *testing.T) {
	root := realTempDir(t)
	withPerfFixRoots(t, root)
	acct := filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(acct, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(acct, ".user.ini")
	original := "memory_limit = 256M\ndisplay_errors = On\nupload_max_filesize = 32M\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	res := FixDisplayErrorsOn(path)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if !strings.Contains(out, "# csm: disabled by remediation -- display_errors = On") {
		t.Errorf("original directive not commented: %q", out)
	}
	if !strings.Contains(out, "display_errors = Off") {
		t.Errorf("Off override not appended: %q", out)
	}
	// Other directives untouched.
	if !strings.Contains(out, "memory_limit = 256M") || !strings.Contains(out, "upload_max_filesize = 32M") {
		t.Errorf("unrelated directives lost: %q", out)
	}
}

func TestFixDisplayErrorsOnPreservesContentAfterLongLine(t *testing.T) {
	root := realTempDir(t)
	withPerfFixRoots(t, root)
	acct := filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(acct, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(acct, ".user.ini")
	longLine := strings.Repeat("a", 2*1024*1024)
	original := "display_errors = On\n" + longLine + "\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	res := FixDisplayErrorsOn(path)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if !strings.Contains(out, longLine) {
		t.Fatal("long config line after display_errors was lost")
	}
	if !strings.Contains(out, "display_errors = Off") {
		t.Fatalf("Off override not appended: %q", out[len(out)-80:])
	}
}

func TestFixDisplayErrorsOnRewritesHtaccess(t *testing.T) {
	root := realTempDir(t)
	withPerfFixRoots(t, root)
	acct := filepath.Join(root, "bob", "public_html")
	if err := os.MkdirAll(acct, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(acct, ".htaccess")
	original := "Options -Indexes\nphp_flag display_errors On\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	res := FixDisplayErrorsOn(path)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	data, _ := os.ReadFile(path)
	out := string(data)
	if !strings.Contains(out, "# csm: disabled by remediation -- php_flag display_errors On") {
		t.Errorf("original directive not commented: %q", out)
	}
	if !strings.Contains(out, "php_flag display_errors Off") {
		t.Errorf(".htaccess Off override not appended: %q", out)
	}
}

func TestFixDisplayErrorsOnNoMatchReturnsError(t *testing.T) {
	root := realTempDir(t)
	withPerfFixRoots(t, root)
	acct := filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(acct, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(acct, ".user.ini")
	if err := os.WriteFile(path, []byte("memory_limit = 256M\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := FixDisplayErrorsOn(path)
	if res.Success {
		t.Fatal("expected refusal when no display_errors line is present")
	}
	if !strings.Contains(res.Error, "no display_errors") {
		t.Errorf("error message = %q, want explanation", res.Error)
	}
}

func TestFixDisplayErrorsOnRefusesWPConfig(t *testing.T) {
	root := realTempDir(t)
	withPerfFixRoots(t, root)
	acct := filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(acct, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(acct, "wp-config.php")
	if err := os.WriteFile(path, []byte("<?php ini_set('display_errors','On');\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := FixDisplayErrorsOn(path)
	if res.Success {
		t.Fatal("automated rewrite of wp-config.php must be refused")
	}
	if !strings.Contains(res.Error, "supports") {
		t.Errorf("error message = %q, want supported-files explanation", res.Error)
	}
}

func TestPerfRemediationRejectsChangedFileBeforeTruncate(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "error_log")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	original, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(root, "replacement")
	if werr := os.WriteFile(tmp, []byte("new"), 0o644); werr != nil {
		t.Fatal(werr)
	}
	if rerr := os.Rename(tmp, path); rerr != nil {
		t.Fatal(rerr)
	}

	err = truncateFilePreservingIdentity(path, original)
	if err == nil {
		t.Fatal("expected changed-file rejection")
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "new" {
		t.Fatalf("changed file was truncated or modified: %q", string(data))
	}
}

func TestPerfRemediationRejectsChangedFileBeforeRename(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, ".user.ini")
	if err := os.WriteFile(path, []byte("display_errors = On\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	original, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(root, "replacement.ini")
	if werr := os.WriteFile(tmp, []byte("memory_limit = 128M\n"), 0o644); werr != nil {
		t.Fatal(werr)
	}
	if rerr := os.Rename(tmp, path); rerr != nil {
		t.Fatal(rerr)
	}

	err = writeFilePreservingOwner(path, []byte("display_errors = Off\n"), original)
	if err == nil {
		t.Fatal("expected changed-file rejection")
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "memory_limit = 128M\n" {
		t.Fatalf("changed file was overwritten: %q", string(data))
	}
}

func fileInode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return inodeOf(info)
}
