package workerproc

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// An inherited writer must not keep the log reader alive after the unit ends.
// Hold a duplicate here instead of leaving an orphan process behind.
func TestUnitWorkerStderrClosesWithUnit(t *testing.T) {
	cfg, _ := fakeUnitConfig(t, "1")
	var logs logCapture
	cfg.Log = logs.logf
	p := launchUnit(t, cfg)
	writer, err := os.OpenFile(fmt.Sprintf("/proc/%d/fd/2", p.PID()), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.WriteString("before exit\n"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(strings.Join(logs.all(), "\n"), `: "before exit"`) {
		if time.Now().After(deadline) {
			t.Fatal("worker stderr was not being read before exit")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := writer.WriteString("final diagnostic"); err != nil {
		t.Fatal(err)
	}
	if err := p.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("unit did not finish while its stderr writer stayed open")
	}
	// POLLERR on a pipe writer means every reader has closed. This also
	// proves cleanup without writing extra bytes into the diagnostic stream.
	fds := []unix.PollFd{{Fd: int32(writer.Fd()), Events: unix.POLLERR}} // #nosec G115 -- Linux descriptors fit in int32.
	deadline = time.Now().Add(5 * time.Second)
	for fds[0].Revents&unix.POLLERR == 0 {
		if _, err := unix.Poll(fds, 20); err != nil && !errors.Is(err, unix.EINTR) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("stderr reader outlived the unit with an inherited writer")
		}
	}
	if _, err := writer.WriteString("after exit\n"); !errors.Is(err, syscall.EPIPE) {
		t.Fatalf("stderr still has a reader after unit exit: %v", err)
	}
	if got := logs.all(); len(got) != 2 || !strings.HasSuffix(got[1], `: "final diagnostic"`) {
		t.Fatalf("final diagnostic was not drained before closing the reader: %q", got)
	}
}
