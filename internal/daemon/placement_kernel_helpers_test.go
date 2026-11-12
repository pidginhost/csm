//go:build linux && kernelintegration

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// mountScratchTmpfs mounts a private tmpfs so the watched device holds only
// this test's entries, and returns its path and stat(2) device.
func mountScratchTmpfs(t *testing.T) (string, uint64) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Mount("tmpfs", dir, "tmpfs", 0, "size=8m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if unmountErr := unix.Unmount(dir, unix.MNT_DETACH); unmountErr != nil {
			t.Error(unmountErr)
		}
	})
	var st unix.Stat_t
	if err = unix.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	return dir, uint64(st.Dev) // #nosec G115 -- device ids are non-negative on Linux
}

func writeScratch(t *testing.T, path string) uint64 {
	t.Helper()
	if err := os.WriteFile(path, []byte("<?php\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return inodeOf(t, path)
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}
