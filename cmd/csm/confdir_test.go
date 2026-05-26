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
	if err := validateConfDir(""); err != nil {
		t.Errorf("empty path should pass through, got %v", err)
	}
}

func TestValidateConfDir_RejectsRelativePath(t *testing.T) {
	err := validateConfDir("conf.d")
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
	err := validateConfDir(missing)
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

	err := validateConfDir(file)
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

	err := validateConfDir(dir)
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

	err := validateConfDir(dir)
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

	if err := validateConfDir(dir); err != nil {
		t.Errorf("safe dir (0750, owned by self) must pass, got %v", err)
	}
}

func TestValidateConfDir_ResolvesSymlinks(t *testing.T) {
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

	err := validateConfDir(link)
	if err == nil {
		t.Fatal("symlink pointing at world-writable dir must be rejected after resolution")
	}
}
