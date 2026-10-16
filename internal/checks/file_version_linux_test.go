//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSameFileVersionDetectsCTimeOnlyChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.php")
	if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if err = os.WriteFile(path, []byte("other"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !sameFileIdentity(before, after) {
		t.Fatal("test did not preserve the legacy file identity checks")
	}
	if SameFileVersion(before, after) {
		t.Fatal("same-inode rewrite with restored mtime was accepted")
	}
}
