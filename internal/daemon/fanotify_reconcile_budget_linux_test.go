//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// Drop recovery re-reads whole directories and scans them inline. Under a
// sustained storm the eager trigger fired every few hundred drops, so recovery
// passes stacked on top of the analyzer pool they were meant to relieve and
// the drops they were recovering from kept growing.

func reconcileBudgetDirs(t *testing.T, fm *FileMonitor, count int) {
	t.Helper()
	root := t.TempDir()
	for i := 0; i < count; i++ {
		dir := filepath.Join(root, strconv.Itoa(i))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "dropped.php")
		if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
			t.Fatal(err)
		}
		fm.recordDroppedDir(path)
	}
}

func TestReconcileDropsDefersDirectoriesPastItsTimeBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		reconcileBudgetDirs(t, fm, 3)
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		scanned := 0
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) {
			scanned++
			time.Sleep(2 * reconcileBudget / 3)
		}

		fm.reconcileDrops()

		if scanned != 2 {
			t.Fatalf("recovery scanned %d directories, want 2 before the %s budget ran out", scanned, reconcileBudget)
		}
		got := requireReconcileQueue(t, fm)
		if got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("deferred directory was not kept for the next pass: %+v", got)
		}
	})
}

func TestReconcileDropsStopsWhenTheMonitorStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		reconcileBudgetDirs(t, fm, 3)
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		scanned := 0
		stop := sync.OnceFunc(func() { close(fm.stopCh) })
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) {
			scanned++
			stop()
		}

		fm.reconcileDrops()

		if scanned != 1 {
			t.Fatalf("recovery scanned %d directories after the monitor stopped, want 1", scanned)
		}
		got := requireReconcileQueue(t, fm)
		if got.Depth != 2 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("directories left by a stopped pass were not kept: %+v", got)
		}
	})
}

func TestReconcileTriggerSkipsPassesInsideTheMinimumInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		reconcileBudgetDirs(t, fm, 1)
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		scanned := 0
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) { scanned++ }

		fm.startReconcile()
		synctest.Wait()
		if scanned != 1 {
			t.Fatalf("first trigger scanned %d directories, want 1", scanned)
		}

		reconcileBudgetDirs(t, fm, 1)
		fm.startReconcile()
		synctest.Wait()
		if scanned != 1 {
			t.Fatalf("second trigger ran %s after the first; scans=%d, want 1", reconcileMinInterval, scanned)
		}

		time.Sleep(reconcileMinInterval)
		fm.startReconcile()
		synctest.Wait()
		if scanned != 2 {
			t.Fatalf("trigger after the minimum interval scanned %d directories, want 2", scanned)
		}
	})
}

func TestReconcileTriggerDoesNotStartAConcurrentPass(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		reconcileBudgetDirs(t, fm, 1)
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		release := make(chan struct{})
		scanned := 0
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) {
			scanned++
			<-release
		}

		fm.startReconcile()
		synctest.Wait()
		reconcileBudgetDirs(t, fm, 1)
		fm.startReconcile()
		synctest.Wait()

		if scanned != 1 {
			t.Fatalf("a second pass ran while one was in flight: scans=%d", scanned)
		}
		close(release)
		fm.wg.Wait()
		got := requireReconcileQueue(t, fm)
		if got.Depth != 1 || got.DroppedTotal != 0 {
			t.Fatalf("work admitted during the pass was lost: %+v", got)
		}
	})
}
