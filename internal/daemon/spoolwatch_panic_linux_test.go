//go:build linux

package daemon

import (
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A malformed message that panics the parser must not take the daemon down:
// Exim would redeliver the same message after every restart and the host
// would crash-loop. The worker recovers, answers the kernel for that event,
// reports once, and keeps serving the queue.
func TestSpoolScanWorkerSurvivesHandlerPanic(t *testing.T) {
	orig := spoolEventHandler
	t.Cleanup(func() { spoolEventHandler = orig })

	var mu sync.Mutex
	var handled []string
	spoolEventHandler = func(sw *SpoolWatcher, evt spoolEvent) {
		mu.Lock()
		handled = append(handled, evt.path)
		mu.Unlock()
		if evt.path == "/spool/bad-D" {
			panic("mime: slice bounds out of range")
		}
	}

	alertCh := make(chan alert.Finding, 8)
	sw := &SpoolWatcher{
		cfg:     &config.Config{},
		alertCh: alertCh,
		scanCh:  make(chan spoolEvent, 4),
		stopCh:  make(chan struct{}),
	}
	// The recovered event still gets its kernel response and fd close: the
	// handler owns evt.fd, so hand it a real descriptor.
	fds := make([]int, 2)
	if err := unix.Pipe2(fds, unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[1]) })

	sw.wg.Add(1)
	go sw.scanWorker()
	sw.scanCh <- spoolEvent{path: "/spool/bad-D", fd: fds[0]}
	sw.scanCh <- spoolEvent{path: "/spool/good-D", fd: -1}
	close(sw.scanCh)

	done := make(chan struct{})
	go func() { sw.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scan worker did not drain the queue after a handler panic")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(handled) != 2 || handled[1] != "/spool/good-D" {
		t.Fatalf("handled = %v, want the event after the panic to be processed", handled)
	}
	select {
	case f := <-alertCh:
		if f.Check != "email_av_scanner_panic" || f.Severity != alert.Critical {
			t.Fatalf("finding = %+v, want critical email_av_scanner_panic", f)
		}
	default:
		t.Fatal("no finding reported for the recovered panic")
	}
}
