//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

// A replaced process directory must not supply the executable inode even
// when its new occupant has a readable executable.
func TestPHPExecutableTrustedPinsDirectory(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "process")
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	proc, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proc.Close() }()
	if err = os.Rename(path, path+"-old"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "binary")
	if err = os.WriteFile(binary, []byte("fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(binary, filepath.Join(path, "exe")); err != nil {
		t.Fatal(err)
	}
	fresh, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	if got, err := phpProcessExeInfo(fresh); err != nil || !os.SameFile(got, want) {
		t.Fatalf("fresh executable = %v, %v; want replacement inode", got, err)
	}
	if got, err := phpProcessExeInfo(proc); !os.IsNotExist(err) || got != nil {
		t.Fatalf("pinned executable = %v, %v; replacement directory supplied an inode", got, err)
	}
}
