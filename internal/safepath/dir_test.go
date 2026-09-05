package safepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTargetPinsParentAcrossAncestorSwap(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	parent := filepath.Join(root, "account")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{parent, outside} {
		if opErr := os.MkdirAll(dir, 0700); opErr != nil {
			t.Fatal(opErr)
		}
	}
	target, err := OpenTarget(root, "account/file", false)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if opErr := os.Rename(parent, parent+".old"); opErr != nil {
		t.Fatal(opErr)
	}
	if opErr := os.Symlink(outside, parent); opErr != nil {
		t.Fatal(opErr)
	}
	if opErr := target.Check(); opErr == nil {
		t.Fatal("replaced parent passed identity check")
	}
	file, err := target.Parent.OpenFile(target.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, opErr := file.WriteString("pinned content"); opErr != nil {
		t.Fatal(opErr)
	}
	if opErr := file.Close(); opErr != nil {
		t.Fatal(opErr)
	}
	got, err := os.ReadFile(filepath.Join(parent+".old", "file"))
	if err != nil || string(got) != "pinned content" {
		t.Fatalf("pinned write = %q, %v", got, err)
	}
	if opErr := target.Parent.RenameTo("file", target.Parent, "renamed"); opErr != nil {
		t.Fatal(opErr)
	}
	if opErr := target.Parent.Remove("renamed"); opErr != nil {
		t.Fatal(opErr)
	}
	for _, dir := range []string{parent + ".old", outside} {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Errorf("directory after pinned rename/removal: %s: %v, %v", dir, entries, err)
		}
	}
}

func TestTargetRejectsSymlinksAndCreatesMissingParents(t *testing.T) {
	root := t.TempDir()
	if opErr := os.Mkdir(filepath.Join(root, "other"), 0700); opErr != nil {
		t.Fatal(opErr)
	}
	if opErr := os.Symlink("other", filepath.Join(root, "account")); opErr != nil {
		t.Fatal(opErr)
	}
	if target, err := OpenTarget(root, "account/missing/file", true); err == nil {
		target.Close()
		t.Fatal("same-root ancestor symlink accepted")
	}
	if _, opErr := os.Stat(filepath.Join(root, "other", "missing")); !os.IsNotExist(opErr) {
		t.Fatalf("created a directory through a symlink: %v", opErr)
	}
	target, err := OpenTarget(root, "new/deep/file", true)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if opErr := target.Check(); opErr != nil {
		t.Fatal(opErr)
	}
	if opErr := os.Symlink(filepath.Join(root, "other"), filepath.Join(root, "new", "deep", "file")); opErr != nil {
		t.Fatal(opErr)
	}
	if file, err := target.Parent.OpenFile(target.Name, os.O_RDONLY, 0); err == nil {
		_ = file.Close()
		t.Fatal("final symlink accepted")
	}
}

func TestRenameDoesNotReplaceDirectory(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"source", "destination"} {
		if opErr := os.Mkdir(filepath.Join(root, name), 0700); opErr != nil {
			t.Fatal(opErr)
		}
	}
	dir, err := OpenDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	before, err := dir.Stat("destination")
	if err != nil {
		t.Fatal(err)
	}
	if opErr := dir.RenameTo("source", dir, "destination"); !os.IsExist(opErr) {
		t.Fatalf("rename over empty directory = %v, want conflict", opErr)
	}
	after, err := dir.Stat("destination")
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("existing directory replaced: %v", err)
	}
	if opErr := dir.RenameTo("source", dir, "new"); opErr != nil {
		t.Fatal(opErr)
	}
	if _, opErr := dir.Stat("source"); !os.IsNotExist(opErr) {
		t.Fatalf("source remains after rename: %v", opErr)
	}
	if info, err := dir.Stat("new"); err != nil || !info.IsDir() {
		t.Fatalf("directory rename failed: %v, %v", info, err)
	}
}

func TestPrivateTempPinsTransactionNames(t *testing.T) {
	root := t.TempDir()
	parent, err := OpenDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	stage, name, err := parent.CreatePrivateTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stage.Close() }()
	info, err := os.Stat(filepath.Join(root, name))
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("staging directory is not private: %v, %v", info, err)
	}
	if opErr := os.Rename(filepath.Join(root, name), filepath.Join(root, "moved")); opErr != nil {
		t.Fatal(opErr)
	}
	if opErr := os.Symlink(".", filepath.Join(root, name)); opErr != nil {
		t.Fatal(opErr)
	}
	file, err := stage.CreateTemp()
	if err != nil {
		t.Fatal(err)
	}
	if opErr := file.Close(); opErr != nil {
		t.Fatal(opErr)
	}
	if _, err := os.Stat(filepath.Join(root, "moved", file.Name())); err != nil {
		t.Fatalf("staged file escaped pinned directory: %v", err)
	}
	if err := parent.RemoveDir("moved"); err == nil {
		t.Fatal("removed a nonempty recovery directory")
	}
	if opErr := stage.Remove(file.Name()); opErr != nil {
		t.Fatal(opErr)
	}
	if opErr := parent.RemoveDir("moved"); opErr != nil {
		t.Fatal(opErr)
	}
	if err := parent.RemoveDir(name); err == nil {
		t.Fatal("followed a replacement symlink during cleanup")
	}
}
