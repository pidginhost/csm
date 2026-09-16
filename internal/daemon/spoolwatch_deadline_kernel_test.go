//go:build linux && kernelintegration

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/config"
)

func TestSpoolDeadlineKernelReleasesPermissionOpen(t *testing.T) {
	for _, mode := range []string{"open", "tempfail", "full", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			shortHoldBudget(t, 50*time.Millisecond)
			dir := t.TempDir()
			path := filepath.Join(dir, "kernel-message-D")
			if err := os.WriteFile(path, []byte("body\n"), 0600); err != nil {
				t.Fatal(err)
			}
			fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_CLOEXEC)
			if err != nil {
				t.Fatal(err)
			}
			sw := &SpoolWatcher{
				fd: fd, cfg: &config.Config{}, permissionMode: true,
				selfPID:    -1, // This test process acts as the external mail opener.
				pipeClosed: 1, stopCh: make(chan struct{}), scanCh: make(chan spoolEvent, 1),
			}
			t.Cleanup(sw.Stop)
			if mode == "tempfail" {
				sw.cfg.EmailAV.FailMode = mode
			}
			if mode == "full" {
				sw.scanCh <- spoolEvent{fd: -1}
			}
			if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM|unix.FAN_EVENT_ON_CHILD, -1, dir); err != nil {
				t.Fatal(err)
			}
			opened := make(chan error, 1)
			go func() {
				f, err := os.Open(path)
				if err == nil {
					err = f.Close()
				}
				opened <- err
			}()
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if n, err := unix.Poll(poll, 2000); err != nil || n != 1 {
				t.Fatalf("permission event not delivered: n=%d err=%v", n, err)
			}
			select {
			case err := <-opened:
				t.Fatalf("open completed without a permission verdict: %v", err)
			default:
			}
			sw.readEvents(make([]byte, 4096))
			var evt spoolEvent
			if mode != "full" {
				evt = <-sw.scanCh
				t.Cleanup(func() { evt.finish(sw, FAN_ALLOW) })
			}
			if mode == "shutdown" {
				sw.Stop()
			}
			select {
			case err := <-opened:
				if mode == "tempfail" {
					if !errors.Is(err, os.ErrPermission) {
						t.Fatalf("tempfail open error = %v, want permission denied", err)
					}
				} else if err != nil {
					t.Fatalf("released open failed: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("mail opener remained suspended")
			}
			if mode != "full" {
				// The opposite late verdict and repeated cleanup must not write
				// a second response or close a recycled descriptor.
				evt.finish(sw, FAN_DENY)
				evt.finish(sw, FAN_ALLOW)
				evt.guard.expire()
				assertFDClosed(t, evt.fd, "kernel event completed")
			}
			if mode != "shutdown" && atomic.LoadInt32(&sw.fdClosed) != 0 {
				t.Fatal("late response broke the live fanotify group")
			}
		})
	}
}
