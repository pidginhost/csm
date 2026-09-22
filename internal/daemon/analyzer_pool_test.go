//go:build linux

package daemon

import (
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

// The analyzer pool never dropped below four workers. On a one or two core
// host that is four content scans competing with the periodic checks and with
// whatever the machine is actually serving.

func TestAnalyzerWorkerCountFollowsTheCoreCount(t *testing.T) {
	for _, tc := range []struct {
		cpus int
		want int
	}{
		{0, minAnalyzerWorkers},
		{1, minAnalyzerWorkers},
		{2, 2},
		{4, 4},
		{16, maxAnalyzerWorkers},
		{64, maxAnalyzerWorkers},
	} {
		if got := analyzerWorkerCount(tc.cpus); got != tc.want {
			t.Errorf("analyzerWorkerCount(%d) = %d, want %d", tc.cpus, got, tc.want)
		}
	}
}

func TestTwoCoreAnalyzerPoolProgressesPastOneSlowScan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := shutdownDrainTestMonitor(4)
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		release := make(chan struct{})
		releaseSlow := sync.OnceFunc(func() { close(release) })
		defer releaseSlow()
		var started, completed atomic.Int32
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) {
			if started.Add(1) == 1 {
				<-release
			}
			completed.Add(1)
		}
		for range analyzerWorkerCount(2) {
			fm.wg.Add(1)
			go fm.analyzerWorker()
		}
		fds := []int{queueShutdownDrainEvent(t, fm)}
		synctest.Wait()
		for range 3 {
			fds = append(fds, queueShutdownDrainEvent(t, fm))
		}
		synctest.Wait()
		if got := completed.Load(); got != 3 {
			t.Errorf("one slow scan blocked the spare worker: completed %d events, want 3", got)
		}
		if status := analyzerQueueStatus(t, fm); status.Depth != 0 || status.InFlight != 1 || status.DroppedTotal != 0 {
			t.Errorf("slow scan hid analyzer progress: %+v", status)
		}
		releaseSlow()
		fm.drainAndClose()
		if got := completed.Load(); got != 4 {
			t.Errorf("pool completed %d events, want 4", got)
		}
		for _, fd := range fds {
			assertFDClosed(t, fd, "completed analyzer event")
		}
	})
}
