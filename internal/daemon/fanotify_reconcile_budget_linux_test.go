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
		if err := os.Chtimes(path, time.Now(), time.Now()); err != nil {
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

func TestReconcileBudgetResumesWithinDirectory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		dir := t.TempDir()
		for _, name := range []string{"a.php", "b.php", "c.php"} {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, time.Now(), time.Now()); err != nil {
				t.Fatal(err)
			}
			fm.recordDroppedDir(path)
		}
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		scans := make(map[string]int)
		fileAnalyzer = func(_ *FileMonitor, event fileEvent) {
			scans[filepath.Base(event.path)]++
			time.Sleep(2 * reconcileBudget / 3)
		}
		fm.reconcileDrops()
		if len(scans) != 2 {
			t.Fatalf("scanned %d files before yielding, want 2", len(scans))
		}
		if got := requireReconcileQueue(t, fm); got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("partial directory was not deferred: %+v", got)
		}
		time.Sleep(2 * reconcileWindow)
		fm.reconcileDrops()
		for _, name := range []string{"a.php", "b.php", "c.php"} {
			if scans[name] != 1 {
				t.Errorf("%s scanned %d times, want once", name, scans[name])
			}
		}
		if got := requireReconcileQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("resumed directory lost its original coverage window: %+v", got)
		}
	})
}

func TestReconcileBudgetStopsWithinDirectory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		dir := t.TempDir()
		for _, name := range []string{"a.php", "b.php"} {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
				t.Fatal(err)
			}
			fm.recordDroppedDir(path)
		}
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		scans := 0
		stop := sync.OnceFunc(func() { close(fm.stopCh) })
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) { scans++; stop() }
		fm.reconcileDrops()
		if scans != 1 {
			t.Fatalf("scanned %d files after stop, want 1", scans)
		}
		fm.drainAndClose()
		if got := requireReconcileQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 {
			t.Fatalf("shutdown did not account for partial directory exactly once: %+v", got)
		}
	})
}

func TestReconcileReporterRetriesWithoutNewDrops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		reconcileBudgetDirs(t, fm, 5)
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		scans := 0
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) { scans++; time.Sleep(2 * reconcileBudget / 3) }
		fm.droppedEvents = 1
		fm.wg.Add(1)
		go fm.overflowReporter()
		synctest.Wait()
		time.Sleep(4 * time.Minute)
		synctest.Wait()
		fm.Stop()
		fm.drainAndClose()
		if scans != 5 {
			t.Fatalf("reporter scanned %d directories, want all 5 without new drops", scans)
		}
		if got := requireReconcileQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("deferred directories expired or disappeared: %+v", got)
		}
	})
}

func TestReconcileBudgetMergesNewDropBehindCursor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		dir := t.TempDir()
		write := func(name string) string {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, time.Now(), time.Now()); err != nil {
				t.Fatal(err)
			}
			return path
		}
		fm.recordDroppedDir(write("b.php"))
		write("z.php")
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		scans := make(map[string]int)
		fileAnalyzer = func(_ *FileMonitor, event fileEvent) {
			name := filepath.Base(event.path)
			scans[name]++
			if name == "b.php" && scans[name] == 1 {
				time.Sleep(reconcileBudget)
				fm.recordDroppedDir(write("a.php"))
			}
		}
		fm.reconcileDrops()
		if got := requireReconcileQueue(t, fm); got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 0 || got.LagSeconds != reconcileBudget.Seconds() {
			t.Fatalf("merge lost the original ticket age or invented a waiting slot: %+v", got)
		}
		time.Sleep(2 * reconcileWindow)
		fm.reconcileDrops()
		if scans["a.php"] != 1 || scans["b.php"] != 2 || scans["z.php"] != 1 {
			t.Fatalf("new drop behind the cursor was not recovered: %v", scans)
		}
		if got := requireReconcileQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("merged recovery was not completed exactly once: %+v", got)
		}
	})
}

func TestReconcileBudgetRetainsReadFailureAcrossPasses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		dir := t.TempDir()
		if err := os.Symlink("a.php", filepath.Join(dir, "a.php")); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"b.php", "c.php"} {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
				t.Fatal(err)
			}
			fm.recordDroppedDir(path)
		}
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		scans := 0
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) { scans++; time.Sleep(reconcileBudget) }
		fm.reconcileDrops()
		if scans != 1 {
			t.Fatalf("scanned %d files, want 1 before yielding", scans)
		}
		fm.reconcileDrops()
		if scans != 2 {
			t.Fatalf("scanned %d files, want 2 after resumption", scans)
		}
		if got := requireReconcileQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 {
			t.Fatalf("later success concealed earlier partial loss: %+v", got)
		}
	})
}

func TestReconcileEmptyTriggerDoesNotDelayNewWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		scans := 0
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) { scans++ }
		fm.startReconcile()
		synctest.Wait()
		reconcileBudgetDirs(t, fm, 1)
		fm.startReconcile()
		synctest.Wait()
		if scans != 1 {
			t.Fatalf("empty pass delayed new work: scans=%d", scans)
		}
	})
}
