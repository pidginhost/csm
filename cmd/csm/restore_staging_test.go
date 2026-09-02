package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Restore staged the whole archive under os.TempDir(), which is a small
// tmpfs on many hosts and a different filesystem from /var/lib, so the
// final rename over the state directory failed with EXDEV after a multi-GB
// extraction. Staging next to the destination keeps the rename atomic.
func TestRestoreStagingRootIsNextToStateDir(t *testing.T) {
	base := t.TempDir()
	dst := BackupSources{StateDir: filepath.Join(base, "state")}
	root, err := restoreStagingRoot(dst)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if filepath.Dir(root) != base {
		t.Fatalf("staging root %s is not under the state dir's parent %s", root, base)
	}
}

func TestRestoreStagingRootFallsBackToTempDir(t *testing.T) {
	root, err := restoreStagingRoot(BackupSources{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if filepath.Dir(root) != filepath.Clean(os.TempDir()) {
		t.Fatalf("staging root %s should fall back to the system temp dir", root)
	}
}
