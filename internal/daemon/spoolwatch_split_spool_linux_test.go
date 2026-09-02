//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// readSpoolEventPaths drains one fanotify read and returns the paths of the
// events it carried, closing each event fd.
func readSpoolEventPaths(t *testing.T, fd int) []string {
	t.Helper()
	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) {
			return nil
		}
		t.Fatalf("read fanotify: %v", err)
	}
	var paths []string
	for off := 0; off+metadataSize <= n; {
		// #nosec G103 -- packed kernel record, bounded by metadataSize.
		meta := (*fanotifyEventMetadata)(unsafe.Pointer(&buf[off]))
		if meta.EventLen < uint32(metadataSize) {
			break
		}
		if meta.Fd >= 0 {
			p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", meta.Fd))
			if err == nil {
				paths = append(paths, p)
			}
			_ = unix.Close(int(meta.Fd))
		}
		off += int(meta.EventLen)
	}
	return paths
}

// On a split spool the message files live one level below the root. Marking
// the root alone misses them; every hash subdirectory must carry its own
// mark, including ones that appear after the watcher started.
func TestSpoolWatcherMarksSplitSpoolSubdirs(t *testing.T) {
	fd, err := unix.FanotifyInit(FAN_CLASS_NOTIF|FAN_CLOEXEC|FAN_NONBLOCK, unix.O_RDONLY)
	if err != nil {
		t.Skipf("fanotify unavailable: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "A"), 0o750); err != nil {
		t.Fatal(err)
	}
	sw := &SpoolWatcher{fd: fd, eventMask: FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD, marked: map[string]struct{}{}}
	if n := sw.markSpoolTargets(root); n != 2 {
		t.Fatalf("marked %d dirs, want root + A", n)
	}

	msg := filepath.Join(root, "A", "1abc-D")
	if err := os.WriteFile(msg, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, p := range readSpoolEventPaths(t, fd) {
		if strings.HasSuffix(p, "/A/1abc-D") {
			seen = true
		}
	}
	if !seen {
		t.Fatal("no close_write event for a message in a split-spool hash directory")
	}

	// A hash directory Exim creates later is picked up by the next rescan
	// and only that directory is newly marked.
	if err := os.Mkdir(filepath.Join(root, "b"), 0o750); err != nil {
		t.Fatal(err)
	}
	if n := sw.markSpoolTargets(root); n != 1 {
		t.Fatalf("rescan marked %d dirs, want only the new one", n)
	}
	late := filepath.Join(root, "b", "2def-D")
	if err := os.WriteFile(late, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	seen = false
	for _, p := range readSpoolEventPaths(t, fd) {
		if strings.HasSuffix(p, "/b/2def-D") {
			seen = true
		}
	}
	if !seen {
		t.Fatal("no close_write event for a message in a hash directory created after start")
	}
}
