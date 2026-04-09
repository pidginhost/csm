package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveExistingFixPath_RejectsSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target.php")
	if err := os.WriteFile(target, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link.php")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	_, _, err := resolveExistingFixPath(link, []string{base})
	if err == nil {
		t.Fatal("resolveExistingFixPath() = nil error, want symlink rejection")
	}
}

func TestResolveExistingFixPath_RejectsOutsideAllowedRoot(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	path := filepath.Join(outside, "file.php")
	if err := os.WriteFile(path, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := resolveExistingFixPath(path, []string{base})
	if err == nil {
		t.Fatal("resolveExistingFixPath() = nil error, want root validation failure")
	}
}

func TestSelectFindingPath_PrefersExplicitFilePath(t *testing.T) {
	got := selectFindingPath("World-writable PHP file: /tmp/ignored.php", "/tmp/explicit.php")
	if got != "/tmp/explicit.php" {
		t.Fatalf("selectFindingPath() = %q, want explicit path", got)
	}
}
