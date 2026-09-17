//go:build linux

package daemon

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSpoolResponseCannotWriteThroughRecycledDescriptor(t *testing.T) {
	original, err := os.CreateTemp(t.TempDir(), "original")
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	replacement, err := os.CreateTemp(t.TempDir(), "replacement")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	const want = "unchanged file\n"
	if _, writeErr := replacement.WriteString(want); writeErr != nil {
		t.Fatal(writeErr)
	}
	if _, seekErr := replacement.Seek(0, 0); seekErr != nil {
		t.Fatal(seekErr)
	}
	// Keep the recycled descriptor above ordinary test-runtime allocations.
	fd, err := unix.FcntlInt(original.Fd(), unix.F_DUPFD_CLOEXEC, 256)
	if err != nil {
		t.Fatal(err)
	}
	watcher := &SpoolWatcher{fd: fd, stopCh: make(chan struct{}), pipeClosed: 1}
	defer watcher.Stop()
	watcher.closeFd()
	recycled, err := unix.FcntlInt(replacement.Fd(), unix.F_DUPFD_CLOEXEC, fd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(recycled) }()
	if recycled != fd {
		t.Fatalf("descriptor was not reused: original=%d replacement=%d", fd, recycled)
	}
	watcher.writeResponse(42, FAN_ALLOW)
	got, err := os.ReadFile(replacement.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("late spool response corrupted an unrelated file: got=%q want=%q", got, want)
	}
	if _, err := unix.FcntlInt(uintptr(recycled), unix.F_GETFD, 0); err != nil {
		t.Fatalf("late spool cleanup closed the replacement descriptor: %v", err)
	}
}
