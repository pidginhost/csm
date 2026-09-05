//go:build !linux && !darwin

package safepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedRenameFailsClosed(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"source", "destination"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := OpenDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	for _, exchange := range []bool{false, true} {
		if err := dir.rename("source", dir, "destination", exchange); err == nil {
			t.Fatalf("unsupported rename succeeded: exchange=%v", exchange)
		}
		if err := dir.rename("source", dir, "absent", exchange); err == nil {
			t.Fatalf("unsupported rename to absent target succeeded: exchange=%v", exchange)
		}
	}
	for _, name := range []string{"source", "destination"} {
		if got, err := os.ReadFile(filepath.Join(root, name)); err != nil || string(got) != name {
			t.Errorf("unsupported rename changed %s: %q, %v", name, got, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "absent")); !os.IsNotExist(err) {
		t.Fatalf("unsupported rename created a destination: %v", err)
	}
}
