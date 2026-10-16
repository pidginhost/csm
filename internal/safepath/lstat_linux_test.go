//go:build linux

package safepath

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLstatWorksWhileChildHasExclusiveLease(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "payload.php")
	if err := os.WriteFile(path, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("close leased file: %v", closeErr)
		}
	}()
	if _, leaseErr := unix.FcntlInt(file.Fd(), unix.F_SETLEASE, unix.F_WRLCK); leaseErr != nil {
		t.Fatal(leaseErr)
	}
	defer func() { _, _ = unix.FcntlInt(file.Fd(), unix.F_SETLEASE, unix.F_UNLCK) }()
	dir, err := OpenDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := dir.Close(); closeErr != nil {
			t.Errorf("close directory: %v", closeErr)
		}
	}()

	info, err := dir.Lstat(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(len("payload")) || !info.Mode().IsRegular() {
		t.Fatalf("unexpected info: size=%d mode=%v", info.Size(), info.Mode())
	}
}
