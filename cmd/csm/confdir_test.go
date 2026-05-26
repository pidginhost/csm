package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateConfDir_AcceptsEmpty(t *testing.T) {
	// Empty path means "operator did not override"; callers fall back to
	// the packaged default, which lives under /etc/csm and is owned by
	// the installer. Validation has nothing to check.
	if got, err := validateConfDir(""); err != nil || got != "" {
		t.Errorf("empty path should pass through, got %v", err)
	}
}

func TestValidateConfDir_RejectsRelativePath(t *testing.T) {
	_, err := validateConfDir("conf.d")
	if err == nil {
		t.Fatal("relative path must be rejected")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Errorf("error must mention absolute requirement, got %v", err)
	}
}

func TestValidateConfDir_RejectsMissingPath(t *testing.T) {
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "does-not-exist")
	_, err := validateConfDir(missing)
	if err == nil {
		t.Fatal("missing path must be rejected")
	}
	if !strings.Contains(err.Error(), "does not exist") && !strings.Contains(err.Error(), "no such") {
		t.Errorf("error must mention missing dir, got %v", err)
	}
}

func TestValidateConfDir_RejectsRegularFile(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := validateConfDir(file)
	if err == nil {
		t.Fatal("regular file must be rejected")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error must mention directory requirement, got %v", err)
	}
}

func TestValidateConfDir_RejectsWorldWritable(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "ww")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err := validateConfDir(dir)
	if err == nil {
		t.Fatal("world-writable directory must be rejected")
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Errorf("error must mention writable, got %v", err)
	}
}

func TestValidateConfDir_RejectsGroupWritable(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "gw")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Re-chmod explicitly because Mkdir applies the process umask, and the
	// developer's umask may strip group-writable bits before the perm
	// check runs.
	if err := os.Chmod(dir, 0770); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err := validateConfDir(dir)
	if err == nil {
		t.Fatal("group-writable directory must be rejected")
	}
}

func TestValidateConfDir_AcceptsSafeDirectory(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "safe")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	if got, err := validateConfDir(dir); err != nil || got != want {
		t.Errorf("safe dir (0750, owned by self) must pass, got %v", err)
	}
}

func TestValidateConfDir_RejectsUnsafeSymlinkTarget(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "real")
	if err := os.Mkdir(target, 0750); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	if err := os.Chmod(target, 0777); err != nil {
		t.Fatalf("chmod target: %v", err)
	}

	link := filepath.Join(tmp, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := validateConfDir(link)
	if err == nil {
		t.Fatal("symlink pointing at world-writable dir must be rejected after resolution")
	}
}

func TestValidateConfDir_ReturnsResolvedSymlink(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "real")
	if err := os.Mkdir(target, 0750); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	got, err := validateConfDir(link)
	if err != nil {
		t.Fatalf("validate symlink: %v", err)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	if got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
}

func TestResolveConfDirFromArgs_FlagOverridesInvalidEnv(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "safe")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("CSM_CONFIG_DIR", "relative-env")

	got, err := resolveConfDirFromArgs([]string{"csm", "validate", "--config-dir", dir})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	if got != want {
		t.Fatalf("conf dir = %q, want %q", got, want)
	}
}

func TestResolveConfDirFromArgs_LastFlagWins(t *testing.T) {
	tmp := t.TempDir()
	first := filepath.Join(tmp, "first")
	second := filepath.Join(tmp, "second")
	if err := os.Mkdir(first, 0750); err != nil {
		t.Fatalf("mkdir first: %v", err)
	}
	if err := os.Mkdir(second, 0750); err != nil {
		t.Fatalf("mkdir second: %v", err)
	}

	got, err := resolveConfDirFromArgs([]string{"csm", "validate", "--config-dir", first, "--config-dir", second})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want, err := filepath.EvalSymlinks(second)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	if got != want {
		t.Fatalf("conf dir = %q, want %q", got, want)
	}
}

func TestResolveConfDirFromArgs_ReturnsErrorInsteadOfExiting(t *testing.T) {
	t.Setenv("CSM_CONFIG_DIR", "relative-env")

	_, err := resolveConfDirFromArgs([]string{"csm", "doctor", "--json"})
	if err == nil {
		t.Fatal("invalid env override must return an error")
	}
	if !strings.Contains(err.Error(), "CSM_CONFIG_DIR refused") {
		t.Fatalf("error = %v, want env refusal", err)
	}
}

func TestResolveConfDirFromArgs_RejectsEmptyFlagValue(t *testing.T) {
	_, err := resolveConfDirFromArgs([]string{"csm", "validate", "--config-dir", ""})
	if err == nil {
		t.Fatal("empty explicit config dir must be rejected")
	}
	if !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("error = %v, want non-empty path refusal", err)
	}
}
