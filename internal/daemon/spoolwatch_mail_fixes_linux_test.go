//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// MAIL-02: a permission event whose pid is our own -- a scan worker opening the
// -D file to parse it -- must be allowed immediately and never handed back to a
// scan worker. Otherwise the scan re-enters this fanotify instance, blocks
// waiting on a verdict that only the (now-blocked) workers can produce, and
// deadlocks email delivery server-wide.
func TestSpoolWatcherDispatchEventSelfPIDAllowsWithoutScanning(t *testing.T) {
	dir := t.TempDir()
	// The event fd must resolve to a "-D" path so that, absent the self-pid
	// short-circuit, dispatchEvent would enqueue it for scanning.
	bodyPath := filepath.Join(dir, "1self0-0000000ABCd-1X-D")
	if err := os.WriteFile(bodyPath, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	evtFd, err := unix.Open(bodyPath, unix.O_RDONLY, 0)
	if err != nil {
		t.Skipf("open body: %v", err)
	}

	// Response pipe so writeResponse succeeds and the verdict can be read back.
	var resp [2]int
	if pipeErr := unix.Pipe2(resp[:], unix.O_CLOEXEC); pipeErr != nil {
		_ = unix.Close(evtFd)
		t.Skipf("pipe2: %v", pipeErr)
	}
	defer func() { _ = unix.Close(resp[0]) }()

	const selfPID = 424242
	sw := &SpoolWatcher{
		fd:             resp[1],
		permissionMode: true,
		selfPID:        selfPID,
		scanCh:         make(chan spoolEvent, 4),
		stopCh:         make(chan struct{}),
	}
	defer sw.closeFd()

	// dispatchEvent owns and closes evtFd on the self path.
	sw.dispatchEvent(int32(evtFd), int32(selfPID))

	// Must NOT be enqueued for scanning.
	select {
	case e := <-sw.scanCh:
		t.Fatalf("self-generated event must not be enqueued, got %+v", e)
	default:
	}

	// Must have been allowed immediately with the event's own fd.
	buf := make([]byte, responseSize)
	n, rerr := unix.Read(resp[0], buf)
	if rerr != nil {
		t.Fatalf("read response: %v", rerr)
	}
	if n != responseSize {
		t.Fatalf("read %d bytes, want %d", n, responseSize)
	}
	got := *(*fanotifyResponse)(unsafe.Pointer(&buf[0]))
	if got.Response != FAN_ALLOW {
		t.Errorf("response = %d, want FAN_ALLOW (%d)", got.Response, FAN_ALLOW)
	}
	if got.Fd != int32(evtFd) {
		t.Errorf("response Fd = %d, want %d", got.Fd, evtFd)
	}
}

// Foreign-pid -D opens must still be enqueued for scanning: the self-pid filter
// is specific, not a blanket skip.
func TestSpoolWatcherDispatchEventForeignPIDEnqueues(t *testing.T) {
	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "1frgn0-0000000ABCd-2Y-D")
	if err := os.WriteFile(bodyPath, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	evtFd, err := unix.Open(bodyPath, unix.O_RDONLY, 0)
	if err != nil {
		t.Skipf("open body: %v", err)
	}

	sw := &SpoolWatcher{
		permissionMode: true,
		selfPID:        111111,
		scanCh:         make(chan spoolEvent, 4),
		stopCh:         make(chan struct{}),
		fdClosed:       1, // no real fanotify fd; the enqueue path never responds
	}

	sw.dispatchEvent(int32(evtFd), int32(222222)) // foreign pid

	select {
	case e := <-sw.scanCh:
		if e.fd != evtFd {
			t.Errorf("enqueued fd = %d, want %d", e.fd, evtFd)
		}
		if !e.needResp {
			t.Error("permission-mode event must set needResp")
		}
		if !strings.HasSuffix(e.path, "-D") {
			t.Errorf("enqueued path = %q, want a -D suffix", e.path)
		}
		_ = unix.Close(e.fd) // a real worker would close it
	default:
		_ = unix.Close(evtFd)
		t.Fatal("foreign-pid -D event must be enqueued for scanning")
	}
}

// MAIL-03: Exim opens the -D body file before it writes the matching -H header
// file. That reception-time open reaches us while the -H is legitimately
// absent (ENOENT). It must be allowed silently in BOTH fail modes: emitting a
// finding would fire once per inbound message, and deferring (tempfail) would
// defer 100% of inbound mail.
func TestSpoolWatcherHandleSpoolEventReceptionRaceAllowsSilently(t *testing.T) {
	for _, failMode := range []string{"open", "tempfail"} {
		t.Run(failMode, func(t *testing.T) {
			dir := t.TempDir()
			msgID := "1recv0-0000000ABCd-3Z"
			bodyPath := filepath.Join(dir, msgID+"-D")
			// -D exists (Exim just wrote it); -H does not yet.
			if err := os.WriteFile(bodyPath, []byte(msgID+"-D\nbody bytes\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			tmpFd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
			if err != nil {
				t.Skipf("open dir: %v", err)
			}

			var respPipe [2]int
			if perr := unix.Pipe2(respPipe[:], unix.O_CLOEXEC); perr != nil {
				_ = unix.Close(tmpFd)
				t.Skipf("pipe2: %v", perr)
			}
			defer func() { _ = unix.Close(respPipe[0]) }()

			cfg := &config.Config{}
			cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
			cfg.EmailAV.FailMode = failMode

			ch := make(chan alert.Finding, 4)
			sw := &SpoolWatcher{
				cfg:     cfg,
				alertCh: ch,
				fd:      respPipe[1],
				stopCh:  make(chan struct{}),
			}
			defer sw.closeFd()

			evt := spoolEvent{path: bodyPath, fd: tmpFd, needResp: true}
			sw.handleSpoolEvent(evt)

			// Must be allowed, never deferred, even in tempfail mode.
			buf := make([]byte, responseSize)
			n, rerr := unix.Read(respPipe[0], buf)
			if rerr != nil {
				t.Fatalf("read response: %v", rerr)
			}
			if n != responseSize {
				t.Fatalf("read %d bytes, want %d", n, responseSize)
			}
			got := *(*fanotifyResponse)(unsafe.Pointer(&buf[0]))
			if got.Response != FAN_ALLOW {
				t.Errorf("response = %d, want FAN_ALLOW (reception race must not defer)", got.Response)
			}

			// Must not emit any finding.
			select {
			case f := <-ch:
				t.Errorf("reception race must not emit a finding, got %+v", f)
			default:
			}
		})
	}
}

func TestSpoolWatcherScanWorkerDrainsQueuedEventsAfterStop(t *testing.T) {
	dir := t.TempDir()

	var respPipe [2]int
	if err := unix.Pipe2(respPipe[:], unix.O_CLOEXEC); err != nil {
		t.Skipf("pipe2: %v", err)
	}
	defer func() { _ = unix.Close(respPipe[0]) }()
	if err := unix.SetNonblock(respPipe[0], true); err != nil {
		t.Skipf("set nonblock: %v", err)
	}

	cfg := &config.Config{}
	cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
	cfg.EmailAV.FailMode = "tempfail"

	const events = 32
	sw := &SpoolWatcher{
		cfg:     cfg,
		alertCh: make(chan alert.Finding, events),
		fd:      respPipe[1],
		scanCh:  make(chan spoolEvent, events),
		stopCh:  make(chan struct{}),
	}
	defer sw.closeFd()

	for i := 0; i < events; i++ {
		evtFd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			t.Skipf("open dir: %v", err)
		}
		sw.scanCh <- spoolEvent{
			path:     filepath.Join(dir, fmt.Sprintf("queued-%02d-D", i)),
			fd:       evtFd,
			needResp: true,
		}
	}

	close(sw.stopCh)
	close(sw.scanCh)
	sw.wg.Add(1)
	sw.scanWorker()

	gotAllows := 0
	buf := make([]byte, responseSize)
	for {
		n, err := unix.Read(respPipe[0], buf)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			break
		}
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if n != responseSize {
			t.Fatalf("read %d bytes, want %d", n, responseSize)
		}
		got := *(*fanotifyResponse)(unsafe.Pointer(&buf[0]))
		if got.Response != FAN_ALLOW {
			t.Fatalf("response = %d, want FAN_ALLOW", got.Response)
		}
		gotAllows++
	}
	if gotAllows != events {
		t.Fatalf("drained responses = %d, want %d queued events", gotAllows, events)
	}
}
