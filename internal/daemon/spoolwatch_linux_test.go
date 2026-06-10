//go:build linux

package daemon

import (
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/config"
)

func TestNewSpoolWatcherLinuxNilConfig(t *testing.T) {
	_, err := NewSpoolWatcher(nil, nil, nil, nil)
	if err == nil {
		t.Fatal("NewSpoolWatcher must reject a nil config")
	}
}

// A failed epoll setup must not leave scanner workers parked on scanCh
// forever: Run starts workers only once epoll is ready and drains them on
// every early-exit path, otherwise daemon shutdown hangs on the leaked
// goroutines and the pipe/fanotify fds leak.
func TestSpoolWatcher_Run_EpollSetupFailureDrainsWorkers(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailAV.ScanConcurrency = 2

	sw := &SpoolWatcher{
		cfg:    cfg,
		fd:     -1, // EpollCtl(EPOLL_CTL_ADD, -1) fails with EBADF
		scanCh: make(chan spoolEvent, 4),
		stopCh: make(chan struct{}),
	}
	if err := unix.Pipe2(sw.pipeFds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		sw.Run()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after epoll setup failure")
	}

	select {
	case _, ok := <-sw.scanCh:
		if ok {
			t.Fatal("scanCh should be closed with no queued events")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scanCh not closed after failed Run - scanner workers leaked")
	}

	if got := atomic.LoadInt32(&sw.fdClosed); got != 1 {
		t.Fatalf("fdClosed = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&sw.pipeClosed); got != 1 {
		t.Fatalf("pipeClosed = %d, want 1", got)
	}

	sw.Stop()
	select {
	case <-sw.stopCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not close stopCh after failed Run")
	}
}
