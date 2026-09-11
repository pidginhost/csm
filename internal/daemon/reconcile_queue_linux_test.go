//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func reconcileQueueTestMonitor() *FileMonitor {
	return &FileMonitor{
		fd: -1, pipeFds: [2]int{-1, -1},
		cfg: &config.Config{}, stopCh: make(chan struct{}),
		analyzerCh: make(chan fileEvent, 1),
	}
}

func requireReconcileQueue(t *testing.T, fm *FileMonitor) queuehealth.Status {
	t.Helper()
	got, exists := (&Daemon{fileMonitor: fm}).QueueStatuses()["fanotify.reconcile"]
	if !exists {
		t.Fatal("reconciliation work has no health row")
	}
	return got
}

func TestReconcileQueueCoalescingPreservesWaitingAge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		dir := t.TempDir()
		fm.recordDroppedDir(filepath.Join(dir, "first.php"))
		if got := requireReconcileQueue(t, fm); got.Depth != 1 || got.DroppedTotal != 0 {
			t.Fatalf("initial recovery admission: %+v", got)
		}
		time.Sleep(40 * time.Second)
		fm.recordDroppedDir(filepath.Join(dir, "second.php"))
		time.Sleep(21 * time.Second)
		got := requireReconcileQueue(t, fm)
		if got.Depth != 1 || got.LagSeconds != 61 || got.Reason != "backlog_lag" || got.DroppedTotal != 0 {
			t.Fatalf("repeated drops concealed the original recovery delay: %+v", got)
		}
		fm.reconcileDrops()
		got = requireReconcileQueue(t, fm)
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" {
			t.Fatalf("completed empty-directory recovery did not clear pressure: %+v", got)
		}
	})
}

func TestReconcileQueueCountsExpiredWorkAfterRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		dir := t.TempDir()
		path := filepath.Join(dir, "first.php")
		if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, time.Now(), time.Now()); err != nil {
			t.Fatal(err)
		}
		fm.recordDroppedDir(path)
		time.Sleep(40 * time.Second)
		fm.recordDroppedDir(filepath.Join(dir, "second.php"))
		time.Sleep(40 * time.Second)
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		calls := 0
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) { calls++ }
		fm.reconcileDrops()
		got := requireReconcileQueue(t, fm)
		if calls != 0 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 {
			t.Fatalf("old recovery obligation disappeared after leaving the scan window: scans=%d status=%+v", calls, got)
		}
	})
}

func TestReconcileQueueRetainsDetachedWorkAndNewAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		path := filepath.Join(t.TempDir(), "candidate.php")
		if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
			t.Fatal(err)
		}
		fm.recordDroppedDir(path)
		requireReconcileQueue(t, fm)
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		releaseScan := sync.OnceFunc(func() { close(release) })
		defer releaseScan()
		calls, scannedFD := 0, -1
		fileAnalyzer = func(_ *FileMonitor, event fileEvent) {
			calls++
			if event.path != path {
				t.Errorf("unexpected recovered path: %q", event.path)
			}
			if calls == 1 {
				scannedFD = event.fd
				close(started)
				<-release
			}
		}
		go func() {
			defer close(done)
			fm.reconcileDrops()
		}()
		synctest.Wait()
		select {
		case <-started:
		case <-done:
			t.Fatal("recovery did not reach the scanner")
		}
		fm.recordDroppedDir(path)
		time.Sleep(61 * time.Second)
		got := requireReconcileQueue(t, fm)
		if got.Depth != 1 || got.InFlight != 1 || got.LagSeconds != 61 || got.ProcessingSeconds != 61 || got.DroppedTotal != 0 {
			t.Fatalf("detached recovery and later work were conflated: %+v", got)
		}
		releaseScan()
		<-done
		assertFDClosed(t, scannedFD, "finished recovery scan")
		got = requireReconcileQueue(t, fm)
		if got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 0 || calls != 1 {
			t.Fatalf("old completion erased newly queued recovery: calls=%d status=%+v", calls, got)
		}
		fm.reconcileDrops()
		got = requireReconcileQueue(t, fm)
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" || calls != 2 {
			t.Fatalf("second recovery did not finish independently: calls=%d status=%+v", calls, got)
		}
	})
}

func TestReconcileQueueCountsUnreadDirectories(t *testing.T) {
	fm := reconcileQueueTestMonitor()
	root := t.TempDir()
	for _, name := range []string{"first", "second", "third"} {
		blocked := filepath.Join(root, name)
		if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		fm.recordDroppedDir(filepath.Join(blocked, "candidate.php"))
	}
	requireReconcileQueue(t, fm)
	fm.reconcileDrops()
	got := requireReconcileQueue(t, fm)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Reason != "dropped_work" {
		t.Fatalf("failed directory reads were recorded as completed recovery: %+v", got)
	}
}

// Bulk unzips and package restores drop events for trees that are gone by the
// time recovery runs. There is nothing left to scan, so the kernel loss that
// started the recovery is the only loss.
func TestReconcileQueueTreatsVanishedDirectoriesAsRecovered(t *testing.T) {
	fm := reconcileQueueTestMonitor()
	root := t.TempDir()
	for _, name := range []string{"first", "second", "third"} {
		fm.recordDroppedDir(filepath.Join(root, name, "candidate.php"))
	}
	requireReconcileQueue(t, fm)
	fm.reconcileDrops()
	got := requireReconcileQueue(t, fm)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" {
		t.Fatalf("directories removed before recovery were counted as lost work: %+v", got)
	}
}

func TestReconcileQueueCountsPartialDirectoryOnce(t *testing.T) {
	fm := reconcileQueueTestMonitor()
	dir := t.TempDir()
	for _, name := range []string{"a-broken.php", "b-broken.php"} {
		if err := os.Symlink(name, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "z-good.php")
	if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := fileAnalyzer
	defer func() { fileAnalyzer = previous }()
	calls := 0
	fileAnalyzer = func(_ *FileMonitor, event fileEvent) {
		calls++
		if event.path != path {
			t.Errorf("scanner received an unreadable candidate: %q", event.path)
		}
	}
	fm.recordDroppedDir(path)
	fm.reconcileDrops()
	got := requireReconcileQueue(t, fm)
	if calls != 1 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 || got.DepthUnit != "directories" {
		t.Fatalf("partial recovery lost valid work or counted files as directories: scans=%d status=%+v", calls, got)
	}
}

func TestReconcileQueuePanicRejectsUnfinishedBatch(t *testing.T) {
	fm := reconcileQueueTestMonitor()
	for range 2 {
		path := filepath.Join(t.TempDir(), "candidate.php")
		if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
			t.Fatal(err)
		}
		fm.recordDroppedDir(path)
	}
	requireReconcileQueue(t, fm)
	previous := fileAnalyzer
	defer func() { fileAnalyzer = previous }()
	calls, scannedFD := 0, -1
	fileAnalyzer = func(_ *FileMonitor, event fileEvent) {
		calls++
		scannedFD = event.fd
		panic("recovery scan failed")
	}
	var caught any
	func() {
		defer func() { caught = recover() }()
		fm.reconcileDrops()
	}()
	got := requireReconcileQueue(t, fm)
	if caught != "recovery scan failed" || calls != 1 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 2 {
		t.Fatalf("panic abandoned detached recovery silently: panic=%v calls=%d status=%+v", caught, calls, got)
	}
	assertFDClosed(t, scannedFD, "panicking recovery scan")
}

func TestReconcileQueueShutdownDiscardsWaitingWorkOnce(t *testing.T) {
	fm := reconcileQueueTestMonitor()
	root := t.TempDir()
	for _, name := range []string{"first", "second", "third"} {
		fm.recordDroppedDir(filepath.Join(root, name, "candidate.php"))
	}
	requireReconcileQueue(t, fm)
	fm.Stop()
	fm.drainAndClose()
	fm.drainAndClose()
	got := requireReconcileQueue(t, fm)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || len(fm.reconcileDirs) != 0 {
		t.Fatalf("shutdown lost or duplicated waiting recovery: pending=%d status=%+v", len(fm.reconcileDirs), got)
	}
}

func TestReconcileQueueShutdownWaitsForRunningWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		path := filepath.Join(t.TempDir(), "candidate.php")
		if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
			t.Fatal(err)
		}
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		started, release, drained := make(chan struct{}), make(chan struct{}), make(chan struct{})
		releaseScan := sync.OnceFunc(func() { close(release) })
		defer releaseScan()
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) {
			close(started)
			<-release
		}
		fm.recordDroppedDir(path)
		fm.wg.Add(1)
		go func() {
			defer fm.wg.Done()
			fm.reconcileDrops()
		}()
		synctest.Wait()
		select {
		case <-started:
		default:
			t.Fatal("recovery did not reach the scanner")
		}
		fm.recordDroppedDir(path)
		fm.Stop()
		go func() {
			defer close(drained)
			fm.drainAndClose()
		}()
		synctest.Wait()
		select {
		case <-drained:
			t.Fatal("shutdown returned while a recovery scan owned work")
		default:
		}
		got := requireReconcileQueue(t, fm)
		if got.Depth != 1 || got.InFlight != 1 || got.DroppedTotal != 0 {
			t.Fatalf("shutdown discarded work before the producer joined: %+v", got)
		}
		releaseScan()
		<-drained
		got = requireReconcileQueue(t, fm)
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 {
			t.Fatalf("shutdown confused completed and abandoned recovery: %+v", got)
		}
	})
}

func TestReconcileQueueExactWindowMatchesScanCutoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm := reconcileQueueTestMonitor()
		for range 3 {
			path := filepath.Join(t.TempDir(), "candidate.php")
			if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, time.Now(), time.Now()); err != nil {
				t.Fatal(err)
			}
			fm.recordDroppedDir(path)
		}
		original := fileAnalyzer
		defer func() { fileAnalyzer = original }()
		calls := 0
		fileAnalyzer = func(_ *FileMonitor, _ fileEvent) { calls++ }
		time.Sleep(reconcileWindow)
		fm.reconcileDrops()
		got := requireReconcileQueue(t, fm)
		if calls != 3 {
			t.Fatalf("files at the cutoff were not scanned: calls=%d", calls)
		}
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" {
			t.Fatalf("complete recovery exactly at the accepted scan cutoff reported loss: %+v", got)
		}
	})
}

func TestReconcileQueuePanicKeepsCompletedDirectories(t *testing.T) {
	fm := reconcileQueueTestMonitor()
	for range 3 {
		path := filepath.Join(t.TempDir(), "candidate.php")
		if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
			t.Fatal(err)
		}
		fm.recordDroppedDir(path)
	}
	original := fileAnalyzer
	defer func() { fileAnalyzer = original }()
	calls := 0
	fileAnalyzer = func(_ *FileMonitor, _ fileEvent) {
		calls++
		if calls == 3 {
			panic("last directory failed")
		}
	}
	var caught any
	func() { defer func() { caught = recover() }(); fm.reconcileDrops() }()
	got := requireReconcileQueue(t, fm)
	if caught != "last directory failed" || calls != 3 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 {
		t.Fatalf("later panic altered completed recovery: caught=%v calls=%d status=%+v", caught, calls, got)
	}
}

func TestReconcileQueueTreatsVanishedCandidatesAsRecovered(t *testing.T) {
	fm := reconcileQueueTestMonitor()
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "absent"), filepath.Join(dir, "a-gone.php")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "z-good.php")
	if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := fileAnalyzer
	defer func() { fileAnalyzer = previous }()
	calls := 0
	fileAnalyzer = func(_ *FileMonitor, event fileEvent) {
		calls++
		if event.path != path {
			t.Errorf("scanner received a candidate that no longer exists: %q", event.path)
		}
	}
	fm.recordDroppedDir(path)
	fm.reconcileDrops()
	got := requireReconcileQueue(t, fm)
	if calls != 1 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" {
		t.Fatalf("a candidate removed before recovery was counted as lost work: scans=%d status=%+v", calls, got)
	}
}
