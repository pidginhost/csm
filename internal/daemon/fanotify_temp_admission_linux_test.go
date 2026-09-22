//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Every write under /tmp, /var/tmp and /dev/shm was queued for analysis, and
// the analyzer then stat'ed the file and returned without a finding for
// anything that was not executable, PHP source, or an image in a hosted tree.
// On a cPanel host those trees carry session files, package work directories
// and database temporaries, so the queue slot, the descriptor and the worker
// wake-up were spent to reach a verdict the reader already had the descriptor
// to make.

func tempAdmissionMonitor(t *testing.T) *FileMonitor {
	t.Helper()
	fm := shutdownDrainTestMonitor(8)
	fm.accountRootPatterns = []string{"/home/*"}
	return fm
}

// tempRootFile writes a file inside a real temp root, which is what the
// admission rule keys on. t.TempDir() already lives under /tmp.
func tempRootFile(t *testing.T, name string, mode os.FileMode) int {
	t.Helper()
	dir, mkErr := os.MkdirTemp("/tmp", "tempadmit-")
	if mkErr != nil {
		t.Fatal(mkErr)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("<?php return true;"), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile honours the umask, and the executable case depends on the mode.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	fd, openErr := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if openErr != nil {
		t.Fatalf("open %s: %v", path, openErr)
	}
	return fd
}

func admitTempEvent(t *testing.T, fm *FileMonitor, fd int) bool {
	t.Helper()
	fm.handleEvent(fd, 0, FAN_CLOSE_WRITE)
	select {
	case event := <-fm.analyzerCh:
		_ = unix.Close(event.fd)
		return true
	default:
		assertFDClosed(t, fd, "event rejected before the queue")
		return false
	}
}

func TestTempRootWriteWithNoSignalIsNotQueued(t *testing.T) {
	fm := tempAdmissionMonitor(t)

	if admitTempEvent(t, fm, tempRootFile(t, "sess_a1b2c3", 0o600)) {
		t.Fatal("a plain temp file was queued for analysis")
	}
	if stats := fm.EventStats(); stats.Received != 1 || stats.Admitted != 0 || stats.Filtered() != 1 {
		t.Fatalf("event accounting: %+v", stats)
	}
}

func TestTempRootExecutableIsQueued(t *testing.T) {
	fm := tempAdmissionMonitor(t)

	if !admitTempEvent(t, fm, tempRootFile(t, "miner", 0o755)) {
		t.Fatal("an executable dropped in a temp root was rejected before analysis")
	}
}

func TestTempRootPHPSourceIsQueued(t *testing.T) {
	fm := tempAdmissionMonitor(t)

	if !admitTempEvent(t, fm, tempRootFile(t, "shell.php", 0o600)) {
		t.Fatal("PHP source in a temp root was rejected before analysis")
	}
}

func TestTempRootHtaccessIsQueued(t *testing.T) {
	fm := tempAdmissionMonitor(t)

	// checkHtaccess runs before the temp-root branch in the analyzer, so a
	// malicious .htaccess staged in /tmp still has to reach it.
	if !admitTempEvent(t, fm, tempRootFile(t, ".htaccess", 0o600)) {
		t.Fatal(".htaccess in a temp root was rejected before analysis")
	}
}

func TestTempRootUserINIIsQueued(t *testing.T) {
	fm := tempAdmissionMonitor(t)

	if !admitTempEvent(t, fm, tempRootFile(t, ".user.ini", 0o600)) {
		t.Fatal(".user.ini in a temp root was rejected before analysis")
	}
}

func TestTempRootConfigDirectoryIsQueued(t *testing.T) {
	fm := tempAdmissionMonitor(t)

	// executable_in_config_realtime is judged inside the analyzer, and it
	// reports on ownership and mode rather than on content.
	if !admitTempEvent(t, fm, tempRootFile(t, ".config/agent", 0o600)) {
		t.Fatal("a file under a temp .config directory was rejected before analysis")
	}
}

func TestTempRootWebshellNameIsQueued(t *testing.T) {
	fm := tempAdmissionMonitor(t)

	if !admitTempEvent(t, fm, tempRootFile(t, "wso.php", 0o600)) {
		t.Fatal("a known webshell filename in a temp root was rejected before analysis")
	}
}

// A write outside the temp roots keeps the path-only decision it always had.
func TestAdmissionOutsideTempRootsIsUnchanged(t *testing.T) {
	fm := tempAdmissionMonitor(t)
	dir := eventFilterDir(t)
	php := openEventFD(t, filepath.Join(dir, "index.php"))
	data := openEventFD(t, filepath.Join(dir, "notes.rst"))

	if !admitTempEvent(t, fm, php) {
		t.Error("PHP source outside the temp roots was rejected")
	}
	if admitTempEvent(t, fm, data) {
		t.Error("a data file outside the temp roots was queued")
	}
}

// An editor saving .htaccess writes a staging file first and renames it into
// place. The admission gate has to resolve that name the same way the filter
// and the analyzer do, or a temp-root staging write of a configuration file is
// dropped before anything reads it.
func TestTempRootAtomicStagingNameIsQueued(t *testing.T) {
	for _, name := range []string{".temp.1..htaccess", ".temp.1..user.ini", ".temp.1.php.ini"} {
		t.Run(name, func(t *testing.T) {
			fm := tempAdmissionMonitor(t)
			if !admitTempEvent(t, fm, tempRootFile(t, name, 0o600)) {
				t.Fatalf("%s was rejected before analysis", name)
			}
		})
	}
}

func TestTempRootAdmissionFailsOpenOnStatError(t *testing.T) {
	fm := tempAdmissionMonitor(t)
	if !fm.tempRootEventNeedsAnalysis("/tmp/session-data", -1) {
		t.Fatal("an uninspectable event descriptor was rejected")
	}
}
