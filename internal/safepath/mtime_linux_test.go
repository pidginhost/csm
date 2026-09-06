//go:build linux

package safepath

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSetModTimePinsInodeAcrossPathReplacement(t *testing.T) {
	root := t.TempDir()
	path, moved := filepath.Join(root, "source"), filepath.Join(root, "moved")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	file, openErr := os.OpenFile(path, os.O_RDWR, 0)
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer file.Close()
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2024, 2, 3, 4, 5, 6, 987654321, time.UTC)
	if setErr := SetModTime(file, stamp); setErr != nil {
		t.Fatal(setErr)
	}
	got, err := os.Stat(moved)
	if err != nil || !got.ModTime().Equal(stamp) {
		t.Fatalf("pinned mtime=%v, error=%v", got, err)
	}
	if got.Sys().(*syscall.Stat_t).Atim != pinned.Sys().(*syscall.Stat_t).Atim {
		t.Fatal("modification-time restore changed access time")
	}
	got, err = os.Stat(path)
	if err != nil || !got.ModTime().Equal(replacement.ModTime()) {
		t.Fatalf("replacement inode was changed: %v, error=%v", got, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := SetModTime(file, stamp); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("closed descriptor error=%v", err)
	}
}
