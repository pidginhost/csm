//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// A filesystem-scoped mark delivers every close-write on the superblock, and
// the path filter discards most of them. Nothing counted either side of that
// filter, so an operator whose daemon was burning a core on events it threw
// away had no number to point at.

func eventCounterMonitor(t *testing.T) *FileMonitor {
	t.Helper()
	fm := shutdownDrainTestMonitor(8)
	fm.accountRootPatterns = []string{"/home/*"}
	return fm
}

// eventFilterDir is deliberately not under /tmp, /var/tmp or /dev/shm: the
// path filter admits every file written in those trees, so a "boring" file
// there would still be analysed.
func eventFilterDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "eventfilter-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func openEventFD(t *testing.T, path string) int {
	t.Helper()
	if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	return fd
}

func TestEventCountersSeparateDeliveredFromAnalysed(t *testing.T) {
	fm := eventCounterMonitor(t)
	dir := eventFilterDir(t)
	interesting := openEventFD(t, filepath.Join(dir, "shell.php"))
	boring := openEventFD(t, filepath.Join(dir, "notes.rst"))

	fm.handleEvent(interesting, 0, FAN_CLOSE_WRITE)
	fm.handleEvent(boring, 0, FAN_CLOSE_WRITE)

	stats := fm.EventStats()
	if stats.Received != 2 {
		t.Errorf("received = %d, want both events", stats.Received)
	}
	if stats.Admitted != 1 {
		t.Errorf("admitted = %d, want only the PHP file", stats.Admitted)
	}
	if got := stats.Filtered(); got != 1 {
		t.Errorf("filtered = %d, want the file the path filter discarded", got)
	}

	// The admitted event still owns its descriptor; the analyzer closes it.
	event := <-fm.analyzerCh
	_ = unix.Close(event.fd)
	assertFDClosed(t, boring, "event the filter discarded")
}

func TestEventCountersCountDroppedEventsAsDelivered(t *testing.T) {
	fm := eventCounterMonitor(t)
	fm.analyzerCh = make(chan fileEvent, 1)
	dir := eventFilterDir(t)

	first := openEventFD(t, filepath.Join(dir, "one.php"))
	second := openEventFD(t, filepath.Join(dir, "two.php"))
	fm.handleEvent(first, 0, FAN_CLOSE_WRITE)
	fm.handleEvent(second, 0, FAN_CLOSE_WRITE)

	stats := fm.EventStats()
	if stats.Received != 2 || stats.Admitted != 1 {
		t.Fatalf("received=%d admitted=%d, want 2 delivered and 1 queued", stats.Received, stats.Admitted)
	}
	if stats.Dropped != 1 {
		t.Fatalf("dropped = %d, want the event the full queue rejected", stats.Dropped)
	}

	event := <-fm.analyzerCh
	_ = unix.Close(event.fd)
	assertFDClosed(t, second, "event dropped by a full queue")
}
