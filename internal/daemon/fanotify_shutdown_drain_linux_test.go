//go:build linux

package daemon

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
	"golang.org/x/sys/unix"
)

// A host whose analyzer queue is deep at SIGTERM used to keep scanning every
// queued event before the daemon could exit. Systemd killed the daemon at
// TimeoutStopSec while the workers were still working through the backlog.

func shutdownDrainTestMonitor(capacity int) *FileMonitor {
	fm := &FileMonitor{
		fd: -1, pipeFds: [2]int{-1, -1},
		cfg: &config.Config{}, stopCh: make(chan struct{}),
		analyzerCh: make(chan fileEvent, capacity),
	}
	fm.initQueueHealth()
	return fm
}

func queueShutdownDrainEvent(t *testing.T, fm *FileMonitor) int {
	t.Helper()
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	fm.analyzerCh <- fileEvent{
		queueTicket: fm.analyzerHealth.Begin(time.Now()),
		path:        "/home/user/public_html/queued.php",
		fd:          fd,
	}
	return fd
}

func analyzerQueueStatus(t *testing.T, fm *FileMonitor) queuehealth.Status {
	t.Helper()
	got, exists := (&Daemon{fileMonitor: fm}).QueueStatuses()["fanotify.analyzer"]
	if !exists {
		t.Fatal("analyzer work has no health row")
	}
	return got
}

func TestShutdownDrainStopsAnalyzingPastItsBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := shutdownDrainTestMonitor(8)
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		var analyzed atomic.Int64
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) {
			analyzed.Add(1)
			// One event consumes the whole budget, so the drain must
			// abandon the rest instead of scanning them.
			time.Sleep(analyzerDrainBudget)
		}
		for i := 0; i < 8; i++ {
			queueShutdownDrainEvent(t, fm)
		}

		fm.wg.Add(1)
		go fm.analyzerWorker()
		started := time.Now()
		fm.drainAndClose()

		if got := analyzed.Load(); got != 1 {
			t.Fatalf("drain analyzed %d events past its budget, want 1", got)
		}
		if elapsed := time.Since(started); elapsed > analyzerDrainBudget {
			t.Fatalf("drain took %s, want at most the %s budget", elapsed, analyzerDrainBudget)
		}
	})
}

func TestShutdownDrainReleasesEventsItAbandons(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := shutdownDrainTestMonitor(8)
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) { time.Sleep(analyzerDrainBudget) }
		fds := make([]int, 0, 8)
		for i := 0; i < 8; i++ {
			fds = append(fds, queueShutdownDrainEvent(t, fm))
		}

		fm.wg.Add(1)
		go fm.analyzerWorker()
		fm.drainAndClose()

		for _, fd := range fds {
			assertFDClosed(t, fd, "event abandoned by the shutdown drain")
		}
		got := analyzerQueueStatus(t, fm)
		if got.DroppedTotal != 7 || got.Depth != 0 || got.InFlight != 0 {
			t.Fatalf("abandoned events left unaccounted: %+v", got)
		}
	})
}
