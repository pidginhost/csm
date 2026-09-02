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

	fds := make([]int, 2)
	if err := unix.Pipe2(fds, unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[1]) })

	fm.wg.Add(1)
	go fm.analyzerWorker()
	fm.analyzerCh <- fileEvent{path: "/home/alice/public_html/bad.php", fd: fds[0]}
	fm.analyzerCh <- fileEvent{path: "/home/alice/public_html/ok.php", fd: -1}
	close(fm.analyzerCh)

	done := make(chan struct{})
	go func() { fm.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("analyzer worker did not drain the queue after a panic")
	}

	// The event fd was closed by the worker even though the analyzer panicked.
	if err := unix.Close(fds[0]); err == nil {
		t.Fatal("event fd still open after the recovered panic")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(analyzed) != 2 || analyzed[1] != "/home/alice/public_html/ok.php" {
		t.Fatalf("analyzed = %v, want the event after the panic to be processed", analyzed)
	}
	select {
	case f := <-alertCh:
		if f.Check != "realtime_scanner_panic" || f.Severity != alert.Critical {
			t.Fatalf("finding = %+v, want critical realtime_scanner_panic", f)
		}
	default:
		t.Fatal("no finding reported for the recovered panic")
	}
}
