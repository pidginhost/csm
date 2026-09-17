//go:build linux

package daemon

import (
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// One crafted file that panics a content analyzer must not take the daemon
// down; the worker recovers, closes the event fd, reports once and keeps
// draining events.
func TestFanotifyAnalyzerWorkerSurvivesPanic(t *testing.T) {
	orig := fileAnalyzer
	t.Cleanup(func() { fileAnalyzer = orig })

	var mu sync.Mutex
	var analyzed []string
	fileAnalyzer = func(fm *FileMonitor, event fileEvent) {
		mu.Lock()
		analyzed = append(analyzed, event.path)
		mu.Unlock()
		if event.path == "/home/alice/public_html/bad.php" {
			panic("regexp: nil dereference")
		}
	}

	alertCh := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alertCh, analyzerCh: make(chan fileEvent, 4)}
	fm.initQueueHealth()

	fds := make([]int, 2)
	if err := unix.Pipe2(fds, unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[1]) })

	fm.wg.Add(1)
	go fm.analyzerWorker()
	fm.analyzerCh <- fileEvent{path: "/home/alice/public_html/bad.php", fd: fds[0], queueTicket: fm.analyzerHealth.Begin(time.Now())}
	for range 2 {
		fm.analyzerCh <- fileEvent{path: "/home/alice/public_html/bad.php", fd: -1, queueTicket: fm.analyzerHealth.Begin(time.Now())}
	}
	fm.analyzerCh <- fileEvent{path: "/home/alice/public_html/ok.php", fd: -1, queueTicket: fm.analyzerHealth.Begin(time.Now())}
	close(fm.analyzerCh)

	done := make(chan struct{})
	go func() { fm.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("analyzer worker did not drain the queue after a panic")
	}

	// The event fd was closed by the worker even though the analyzer panicked.
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("event fd still open after the recovered panic: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(analyzed) != 4 || analyzed[3] != "/home/alice/public_html/ok.php" {
		t.Fatalf("analyzed = %v, want the event after the panic to be processed", analyzed)
	}
	if got := fm.analyzerHealth.Snapshot(time.Now()); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Reason != "dropped_work" || got.Status != "degraded" {
		t.Fatalf("recovered analyzer panic was counted as completed protection: %+v", got)
	}
	select {
	case f := <-alertCh:
		if f.Check != "realtime_scanner_panic" || f.Severity != alert.Critical {
			t.Fatalf("finding = %+v, want critical realtime_scanner_panic", f)
		}
	default:
		t.Fatal("no finding reported for the recovered panic")
	}
	if len(alertCh) != 0 {
		t.Fatalf("scanner panic findings were not bounded: %d extra", len(alertCh))
	}
}
