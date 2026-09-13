package main

import (
	"os"
	"path/filepath"
	"strings"
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

// Standalone upgrades refresh the unit through rehash, never through install
// or the package. systemd refuses to build the mount namespace when an
// unprefixed ReadWritePaths entry is missing (status=226/NAMESPACE), so a
// host installed before a grant existed could not start after the upgrade.
func TestWriteSystemdServiceUnitCreatesRequiredWritablePaths(t *testing.T) {
	root := t.TempDir()
	oldRoot := systemdSandboxRoot
	systemdSandboxRoot = root
	oldPath := systemdUnitPath
	systemdUnitPath = filepath.Join(root, "csm.service")
	t.Cleanup(func() {
		systemdSandboxRoot = oldRoot
		systemdUnitPath = oldPath
	})

	hostDirs := map[string]os.FileMode{
		"/tmp":     0o777 | os.ModeSticky,
		"/var/tmp": 0o755,
	}
	for dir, mode := range hostDirs {
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}

	// An existing grant keeps the mode the operator or installer gave it.
	rules := filepath.Join(root, "opt/csm/rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rules, 0o755); err != nil {
		t.Fatal(err)
	}

	unit := systemdServiceUnit("/opt/csm/csm")
	if err := writeSystemdServiceUnit(unit); err != nil {
		t.Fatal(err)
	}

	systemdCreatedPaths := map[string]bool{
		"/etc/csm":     true,
		"/var/lib/csm": true,
		"/var/log/csm": true,
	}
	for path := range unitDirectiveFields(unit, "ReadWritePaths") {
		if strings.HasPrefix(path, "-") {
			if _, err := os.Stat(filepath.Join(root, strings.TrimPrefix(path, "-"))); err == nil {
				t.Errorf("tolerate-absent grant %s was created", path)
			}
			continue
		}
		_, err := os.Stat(filepath.Join(root, path))
		if systemdCreatedPaths[path] {
			if err == nil {
				t.Errorf("%s is created by systemd with the unit's mode; rehash must not pre-create it", path)
			}
			continue
		}
		if err != nil {
			t.Errorf("unprefixed ReadWritePaths entry %s missing after unit write: %v", path, err)
		}
	}

	info, err := os.Stat(filepath.Join(root, "opt/csm/quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Errorf("quarantine = %v, want directory with mode 0700", info.Mode())
	}
	info, err = os.Stat(rules)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("existing rules dir mode changed to %v", info.Mode().Perm())
	}
	for dir, want := range hostDirs {
		info, err := os.Stat(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode() & (os.ModePerm | os.ModeSticky); got != want {
			t.Errorf("existing host directory %s mode = %v, want %v", dir, got, want)
		}
	}
	if _, err := os.Stat(systemdUnitPath); err != nil {
		t.Errorf("unit not written: %v", err)
	}
}

// A grant that cannot be created must stop the unit write, so rehash fails
// and the upgrade rolls back instead of installing a unit that cannot start.
func TestWriteSystemdServiceUnitKeepsOldUnitWhenGrantCannotBeCreated(t *testing.T) {
	root := t.TempDir()
	oldRoot := systemdSandboxRoot
	systemdSandboxRoot = root
	oldPath := systemdUnitPath
	systemdUnitPath = filepath.Join(root, "csm.service")
	t.Cleanup(func() {
		systemdSandboxRoot = oldRoot
		systemdUnitPath = oldPath
	})

	if err := os.WriteFile(systemdUnitPath, []byte("[Unit]\nDescription=old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A regular file where /opt/csm is expected makes the grant uncreatable.
	if err := os.MkdirAll(filepath.Join(root, "opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "opt/csm"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeSystemdServiceUnit(systemdServiceUnit("/opt/csm/csm")); err == nil {
		t.Fatal("unit write succeeded although a required grant could not be created")
	}
	data, err := os.ReadFile(systemdUnitPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "[Unit]\nDescription=old\n" {
		t.Errorf("unit replaced despite failed grant: %q", data)
	}
}
