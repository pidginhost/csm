//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// classifyFixture writes name under dir with mode and returns its path and a
// read-only descriptor, as fanotify would hand the reader.
func classifyFixture(t *testing.T, dir, name string, mode os.FileMode) (string, int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("<?php return true;"), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile honours the umask, and the executable case depends on the mode.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return path, fd
}

func TestClassifyEventAdmission(t *testing.T) {
	home := t.TempDir()
	t.Cleanup(checks.SetAccountHomeRootsForTest([]string{home}))
	fm := newFileMonitorCore(&config.Config{StatePath: t.TempDir()}, make(chan alert.Finding, 1))

	realPrefixes := tempRootPrefixes
	t.Cleanup(func() { tempRootPrefixes = realPrefixes })

	check := func(t *testing.T, path string, fd int, wantAdmit bool) {
		t.Helper()
		ev, admit := fm.classifyEvent(path, fd)
		if admit != wantAdmit {
			t.Fatalf("classifyEvent(%s) admit = %v, want %v", path, admit, wantAdmit)
		}
		if !admit {
			// handleEvent owns the close on rejection.
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
				t.Fatalf("classifyEvent closed fd of a rejected event: %v", err)
			}
			return
		}
		if ev.path != path || ev.fd != fd || ev.dropperOnly || ev.phpExecutable {
			t.Fatalf("event = %+v, want path %s fd %d content-admitted", ev, path, fd)
		}
	}

	// t.TempDir() sits under /tmp in the container, so the account tree must
	// not be judged as a temp root.
	tempRootPrefixes = nil
	docroot := filepath.Join(home, "acct", "public_html")
	for _, tc := range []struct {
		name  string
		admit bool
	}{
		{"x.php", true},
		{"x.js", false},
		{".htaccess", true},
	} {
		t.Run("account/"+tc.name, func(t *testing.T) {
			path, fd := classifyFixture(t, docroot, tc.name, 0o644)
			check(t, path, fd, tc.admit)
		})
	}

	tempRootPrefixes = realPrefixes
	tmp, err := os.MkdirTemp("/tmp", "classify-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	for _, tc := range []struct {
		name  string
		mode  os.FileMode
		admit bool
	}{
		{"x.php", 0o644, true},
		// The path filter admits every temp-root write; only the descriptor
		// check can tell these two apart.
		{"sess_a1b2", 0o600, false},
		{"miner", 0o755, true},
	} {
		t.Run("temp/"+tc.name, func(t *testing.T) {
			path, fd := classifyFixture(t, tmp, tc.name, tc.mode)
			if !fm.isInteresting(path) {
				t.Fatalf("isInteresting(%s) = false; the case no longer reaches the temp-root check", path)
			}
			check(t, path, fd, tc.admit)
		})
	}
}

// Quarantine and pre-clean copies keep the name of the file they came from.
// Admitting them re-scans malware CSM already moved and spends an automatic
// response on a copy it can never act on.
func TestClassifyEventSkipsQuarantineCopies(t *testing.T) {
	t.Cleanup(checks.SetAccountHomeRootsForTest([]string{t.TempDir()}))
	quarantine := filepath.Join(t.TempDir(), "quarantine")
	t.Cleanup(checks.SetQuarantineDirForTest(quarantine))
	fm := newFileMonitorCore(&config.Config{StatePath: t.TempDir()}, make(chan alert.Finding, 1))
	realPrefixes := tempRootPrefixes
	t.Cleanup(func() { tempRootPrefixes = realPrefixes })
	tempRootPrefixes = nil

	for _, dir := range []string{quarantine, filepath.Join(quarantine, "pre_clean")} {
		path, fd := classifyFixture(t, dir, "20261109-120000_k_home_acct_public_html_x.php", 0o600)
		if _, admit := fm.classifyEvent(path, fd); admit {
			t.Errorf("classifyEvent admitted quarantine copy %s", path)
		}
	}
	path, fd := classifyFixture(t, quarantine+"-other", "x.php", 0o644)
	if _, admit := fm.classifyEvent(path, fd); !admit {
		t.Errorf("classifyEvent rejected %s, which is outside the quarantine", path)
	}
}
