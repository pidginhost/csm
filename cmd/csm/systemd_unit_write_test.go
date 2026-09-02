package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The service unit was rewritten in place with a truncating write on every
// rehash; systemd parsing the file mid-write saw an empty or partial unit.
// An atomic replace lands a new inode via rename.
func TestWriteSystemdServiceUnitReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.service")
	if err := os.WriteFile(path, []byte("[Unit]\nDescription=old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	old := systemdUnitPath
	systemdUnitPath = path
	t.Cleanup(func() { systemdUnitPath = old })

	if err = writeSystemdServiceUnit("[Unit]\nDescription=new\n"); err != nil {
		t.Fatal(err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if inode(before) == inode(after) {
		t.Fatal("unit file rewritten in place; expected a rename onto a new inode")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "[Unit]\nDescription=new\n" {
		t.Fatalf("content = %q", data)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
