//go:build linux

package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestInotifyQueuesReportVariableLengthBacklog(t *testing.T) {
	for _, name := range []string{"forwarder", "phprelay"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				root := t.TempDir()
				var source any
				var fd int
				var drain, closeWatcher func()
				var paths []string
				if name == "forwarder" {
					old := valiasesDir
					valiasesDir = root
					defer func() { valiasesDir = old }()
					fw, err := NewForwarderWatcher(make(chan alert.Finding, 4), nil)
					if err != nil {
						t.Fatal(err)
					}
					source, fd = fw, fw.inotifyFd
					paths = []string{filepath.Join(root, "a.test"), filepath.Join(root, strings.Repeat("a", 80)+".test")}
					drain = func() { fw.readEvents(make([]byte, 4096)) }
					closeWatcher = func() {
						stop := make(chan struct{})
						close(stop)
						fw.Run(stop)
					}
				} else {
					sub := filepath.Join(root, "k")
					if err := os.Mkdir(sub, 0o700); err != nil {
						t.Fatal(err)
					}
					paths = []string{filepath.Join(sub, "a-H"), filepath.Join(sub, strings.Repeat("a", 80)+"-H")}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					seen := map[string]int{}
					w, err := newSpoolWatcher(root, func(path string) {
						seen[path]++
						if len(seen) == 2 {
							cancel()
						}
					})
					if err != nil {
						t.Fatal(err)
					}
					source, fd = w, w.fd
					drain = func() {
						w.Run(ctx)
						if len(seen) != 2 || seen[paths[0]] != 1 || seen[paths[1]] != 1 {
							t.Fatalf("spool reader lost or duplicated events: %v", seen)
						}
					}
					closeWatcher = func() {
						if err := w.Close(); err != nil {
							t.Error(err)
						}
					}
				}
				defer closeWatcher()
				for _, path := range paths {
					if err := os.WriteFile(path, []byte("local: local\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				pending, err := unix.IoctlGetInt(fd, unix.TIOCINQ)
				if err != nil || pending != 144 {
					t.Fatalf("expected two different-sized kernel records: bytes=%d err=%v", pending, err)
				}
				provider, ok := source.(queueSource)
				if !ok {
					t.Fatal("inotify backlog has no health provider")
				}
				d := &Daemon{}
				d.registerQueueSource(name, provider)
				got := d.QueueStatuses()[name+".kernel"]
				if got.Depth != pending || got.DepthUnit != "bytes" || !got.CapacityUnavailable || got.DepthUnavailable || got.Status != "ok" {
					t.Fatalf("variable-length notifications were miscounted: %+v", got)
				}
				time.Sleep(61 * time.Second)
				got = d.QueueStatuses()[name+".kernel"]
				if got.Reason != "consumer_stalled" || got.LagSeconds != 61 || got.Depth != pending {
					t.Fatalf("unread inotify queue stayed healthy: %+v", got)
				}
				drain()
				got = d.QueueStatuses()[name+".kernel"]
				reader := d.QueueStatuses()[name+".reader"]
				if got.Depth != 0 || got.DroppedTotal != 0 || got.Status != "ok" || reader.InFlight != 0 || reader.DroppedTotal != 0 {
					t.Fatalf("drained inotify queue did not recover: kernel=%+v reader=%+v", got, reader)
				}
			})
		})
	}
}

func TestForwarderQueueRegisteredAtStartup(t *testing.T) {
	old := valiasesDir
	valiasesDir = t.TempDir()
	defer func() { valiasesDir = old }()
	d := &Daemon{cfg: &config.Config{}, stopCh: make(chan struct{}), alertCh: make(chan alert.Finding, 1)}
	d.startForwarderWatcher()
	defer func() { close(d.stopCh); d.wg.Wait() }()
	if got, exists := d.QueueStatuses()["forwarder.kernel"]; !exists || got.DepthUnit != "bytes" || got.Status != "ok" {
		t.Fatalf("started forwarder watcher omitted queue health: exists=%v status=%+v", exists, got)
	}
}

func TestForwarderQueueCountsOverflowMarkers(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) }()
	data := make([]byte, 3*unix.SizeofInotifyEvent)
	for offset := 0; offset < len(data); offset += unix.SizeofInotifyEvent {
		binary.NativeEndian.PutUint32(data[offset:offset+4], ^uint32(0))
		binary.NativeEndian.PutUint32(data[offset+4:offset+8], unix.IN_Q_OVERFLOW)
	}
	if n, err := unix.Write(fds[1], data); err != nil || n != len(data) {
		t.Fatalf("write overflow records: n=%d err=%v", n, err)
	}
	fw := &ForwarderWatcher{inotifyFd: fds[0]}
	fw.readEvents(make([]byte, 4096))
	provider, ok := any(fw).(queueSource)
	if !ok {
		t.Fatal("forwarder overflow has no health provider")
	}
	got := provider.QueueStatuses(time.Now())["kernel"]
	if got.DroppedTotal != 3 || !got.DroppedLowerBound || got.Status != "degraded" || got.Reason != "dropped_work" {
		t.Fatalf("inotify overflow markers disappeared: %+v", got)
	}
}

func TestInotifyCloseCannotCloseRecycledDescriptor(t *testing.T) {
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
	fd, err := unix.FcntlInt(original.Fd(), unix.F_DUPFD_CLOEXEC, 256)
	if err != nil {
		t.Fatal(err)
	}
	w := &spoolWatcher{fd: fd}
	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	recycled, err := unix.FcntlInt(replacement.Fd(), unix.F_DUPFD_CLOEXEC, fd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(recycled) }()
	if recycled != fd {
		t.Fatalf("descriptor was not reused: old=%d replacement=%d", fd, recycled)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(recycled), unix.F_GETFD, 0); err != nil {
		t.Fatalf("repeated watcher close closed an unrelated descriptor: %v", err)
	}
	if err := w.addSubdir(t.TempDir()); !errors.Is(err, unix.EBADF) {
		t.Fatalf("late watch change reached a recycled descriptor: %v", err)
	}
}

func TestInotifyWatcherWaitSupportsHighDescriptor(t *testing.T) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	high, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 1024)
	_ = unix.Close(fd)
	if err != nil {
		t.Fatal(err)
	}
	w := &spoolWatcher{fd: high}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var caught any
	func() {
		defer func() { caught = recover() }()
		w.Run(ctx)
	}()
	if caught != nil {
		t.Fatalf("idle notification queue panicked for fd %d: %v", high, caught)
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("idle watcher exited before cancellation: %v", ctx.Err())
	}
	assertFDClosed(t, high, "completed inotify watcher")
}

func TestInotifyCloseCountsUnreadWorkAsLowerBound(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "k")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	w, err := newSpoolWatcher(root, func(string) { t.Error("closed watcher processed an event") })
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first-H", "second-H"} {
		if err := os.WriteFile(filepath.Join(sub, name), []byte("queued\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	provider, ok := any(w).(queueSource)
	if !ok {
		t.Fatal("closed inotify watcher has no health provider")
	}
	got := provider.QueueStatuses(time.Now())["kernel"]
	if got.Depth != 0 || got.DroppedTotal != 1 || !got.DroppedLowerBound {
		t.Fatalf("unread bytes were lost or reported as an exact event count: %+v", got)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if again := provider.QueueStatuses(time.Now())["kernel"]; again.DroppedTotal != got.DroppedTotal {
		t.Fatalf("repeated close duplicated losses: before=%+v after=%+v", got, again)
	}
}

func TestInotifyQueueRetainsBlockedCallbackThroughClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		root := t.TempDir()
		sub := filepath.Join(root, "k")
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		releaseCallback := sync.OnceFunc(func() { close(release) })
		defer releaseCallback()
		calls := 0
		w, err := newSpoolWatcher(root, func(string) {
			calls++
			close(started)
			<-release
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = w.Close() }()
		provider, ok := any(w).(queueSource)
		if !ok {
			t.Fatal("inotify reader has no health provider")
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := os.WriteFile(filepath.Join(sub, "first-H"), []byte("queued\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		go func() { defer close(done); w.Run(ctx) }()
		<-started
		if err := os.WriteFile(filepath.Join(sub, "second-H"), []byte("queued\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		provider.QueueStatuses(time.Now())
		time.Sleep(61 * time.Second)
		states := provider.QueueStatuses(time.Now())
		kernel, reader := states["kernel"], states["reader"]
		if kernel.Depth != 32 || kernel.Reason != "consumer_stalled" || reader.InFlight != 1 || reader.ProcessingSeconds != 61 {
			t.Fatalf("blocked callback concealed owned and queued work: kernel=%+v reader=%+v", kernel, reader)
		}
		cancel()
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		states = provider.QueueStatuses(time.Now())
		kernel, reader = states["kernel"], states["reader"]
		if kernel.Depth != 0 || kernel.DroppedTotal != 1 || reader.InFlight != 1 || reader.DroppedTotal != 0 {
			t.Fatalf("close erased running work or confused unread bytes with event counts: kernel=%+v reader=%+v", kernel, reader)
		}
		releaseCallback()
		<-done
		states = provider.QueueStatuses(time.Now())
		if calls != 1 || states["reader"].InFlight != 0 || states["reader"].DroppedTotal != 0 || states["kernel"].DroppedTotal != 1 {
			t.Fatalf("callback completion corrupted shutdown accounting: calls=%d states=%+v", calls, states)
		}
	})
}

func TestPHPRelayQueueCountsOverflowMarkers(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fds[1]) }()
	data := make([]byte, 3*unix.SizeofInotifyEvent)
	for offset := 0; offset < len(data); offset += unix.SizeofInotifyEvent {
		binary.NativeEndian.PutUint32(data[offset:offset+4], ^uint32(0))
		binary.NativeEndian.PutUint32(data[offset+4:offset+8], unix.IN_Q_OVERFLOW)
	}
	if n, err := unix.Write(fds[1], data); err != nil || n != len(data) {
		t.Fatalf("write overflow records: n=%d err=%v", n, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &spoolWatcher{fd: fds[0]}
	calls := 0
	w.SetOverflowHandler(func() {
		calls++
		if calls == 3 {
			cancel()
		}
	})
	w.Run(ctx)
	provider, ok := any(w).(queueSource)
	if !ok {
		t.Fatal("PHP relay overflow has no health provider")
	}
	states := provider.QueueStatuses(time.Now())
	got := states["kernel"]
	if calls != 3 || w.OverflowCount() != 3 || got.DroppedTotal != 3 || !got.DroppedLowerBound || got.Reason != "dropped_work" || states["reader"].DroppedTotal != 0 {
		t.Fatalf("overflow evidence was lost or disrupted recovery callbacks: calls=%d status=%+v", calls, states)
	}
	replacement, err := newSpoolWatcher(t.TempDir(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replacement.Close() }()
	replacement.inheritQueueHealth(w)
	d := &Daemon{}
	d.registerQueueSource("phprelay", replacement)
	got = d.QueueStatuses()["phprelay.kernel"]
	if got.Depth != 0 || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Reason != "dropped_work" {
		t.Fatalf("restart cleared kernel overflow evidence: %+v", got)
	}
}

func TestInotifyReplacementRetainsFailedWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		root := t.TempDir()
		sub := filepath.Join(root, "k")
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		var previous *spoolWatcher
		d := &Daemon{}
		for attempt := range 3 {
			w, err := newSpoolWatcher(root, func(string) { panic("callback failed") })
			if err != nil {
				t.Fatal(err)
			}
			if previous != nil {
				w.inheritQueueHealth(previous)
			}
			d.registerQueueSource("phprelay", w)
			previous = w
			if err := os.WriteFile(filepath.Join(sub, "candidate-H"), []byte("queued\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var caught any
			func() {
				defer func() { caught = recover() }()
				w.Run(context.Background())
			}()
			if caught != "callback failed" {
				t.Fatalf("callback did not fail: %v", caught)
			}
			states := d.QueueStatuses()
			reader := states["phprelay.reader"]
			if reader.InFlight != 0 || reader.DroppedTotal != uint64(attempt+1) || states["phprelay.kernel"].Depth != 0 {
				t.Fatalf("replacement concealed failed callback: attempt=%d status=%+v", attempt, states)
			}
		}
		if got := d.QueueStatuses()["phprelay.reader"]; got.RecentDrops != 3 || got.Reason != "dropped_work" {
			t.Fatalf("repeated callback failures never degraded health: %+v", got)
		}
		replacement, err := newSpoolWatcher(root, func(string) {})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = replacement.Close() }()
		replacement.inheritQueueHealth(previous)
		if err := os.WriteFile(filepath.Join(sub, "fresh-H"), []byte("queued\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		d.registerQueueSource("phprelay", replacement)
		previous.QueueStatuses(time.Now())
		got := d.QueueStatuses()
		if got["phprelay.kernel"].Depth != 32 || got["phprelay.kernel"].LagSeconds != 0 || got["phprelay.reader"].DroppedTotal != 3 {
			t.Fatalf("replacement inherited old occupancy or lost earlier failures: %+v", got)
		}
	})
}
