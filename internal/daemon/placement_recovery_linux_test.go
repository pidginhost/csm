//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

// The BPF hook runs before the rename. Recovery must not retire the work
// just because it reaches the destination before the kernel places it.
func TestDroppedPlacementWaitsForPendingRename(t *testing.T) {
	for _, directory := range []bool{false, true} {
		name := "file"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fm, _ := placedDirTestMonitor(t)
				staged := stagedTree(t, map[string]string{"x.php": "<?php echo 1;"})
				if !directory {
					staged = filepath.Join(staged, "x.php")
				}
				path := filepath.Join(t.TempDir(), "placed")
				want := filepath.Join(path, "x.php")
				if !directory {
					path += ".php"
					want = path
				}
				ev := placementOf(t, staged, writerPID)
				ev.Path, ev.IsDir = path, directory
				fm.recoverDroppedPlacement(ev)
				renamed := make(chan error, 1)
				defer func() {
					if err := <-renamed; err != nil {
						t.Error(err)
					}
				}()
				go func() {
					time.Sleep(25 * time.Millisecond)
					renamed <- os.Rename(staged, path)
				}()
				var scanned []string
				if directory {
					walkAllPlacedDirs(fm)
					scanned = walkedPaths(t, fm)
				} else {
					previous := fileAnalyzer
					defer func() { fileAnalyzer = previous }()
					fileAnalyzer = func(_ *FileMonitor, event fileEvent) {
						scanned = append(scanned, event.path)
					}
					fm.reconcileDrops()
					if got := requireReconcileQueue(t, fm); got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 0 {
						t.Fatalf("pending rename retired before placement: %+v", got)
					}
					time.Sleep(time.Second)
					fm.reconcileDrops()
				}
				if !slices.Equal(scanned, []string{want}) {
					t.Fatalf("recovered %v, want [%s]", scanned, want)
				}
			})
		})
	}
}

// A continuing rename flood must not defer checks of files already present.
// New intent still needs a later pass after its visibility window ends.
func TestDroppedPlacementRecoveryMakesProgressDuringFlood(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm, _ := placedDirTestMonitor(t)
		path := filepath.Join(stagedTree(t, map[string]string{"x.php": "<?php echo 1;"}), "x.php")
		ev := placementOf(t, path, writerPID)
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		scanned := 0
		fileAnalyzer = func(_ *FileMonitor, event fileEvent) {
			if event.path != path {
				t.Fatalf("scanned %s, want %s", event.path, path)
			}
			scanned++
		}
		for i := 1; i <= 3; i++ {
			fm.recoverDroppedPlacement(ev)
			fm.recordDroppedDir(path)
			fm.reconcileDrops()
			if scanned != i {
				t.Fatalf("flood postponed recovery: scanned %d times, want %d", scanned, i)
			}
			if got := requireReconcileQueue(t, fm); got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 0 {
				t.Fatalf("pending placement lost or duplicated: %+v", got)
			}
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(time.Second)
		fm.reconcileDrops()
		if scanned != 4 {
			t.Fatalf("final recovery scanned %d times, want 4", scanned)
		}
		if got := requireReconcileQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("completed placement left pending work: %+v", got)
		}
	})
}

func TestDroppedDirectoryRecoveryStopsDuringRenameWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm, _ := placedDirTestMonitor(t)
		ev := placementOf(t, stagedTree(t, map[string]string{"x.php": "<?php echo 1;"}), writerPID)
		ev.IsDir = true
		fm.recoverDroppedPlacement(ev)
		started := time.Now()
		go func() {
			time.Sleep(time.Millisecond)
			close(fm.stopCh)
		}()
		walkAllPlacedDirs(fm)
		if time.Since(started) != time.Millisecond {
			t.Fatalf("shutdown waited for rename: %v", time.Since(started))
		}
		if events := queuedPlacements(t, fm); len(events) != 0 {
			t.Fatalf("shutdown admitted %d files", len(events))
		}
		if got := requirePlacedDirQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 {
			t.Fatalf("abandoned walk not accounted for: %+v", got)
		}
	})
}

// A scan that yields before a pending rename becomes visible cannot resume
// past the new name on its next pass.
func TestDroppedPlacementRecoveryResetsEarlyCursor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fm, _ := placedDirTestMonitor(t)
		dir := stagedTree(t, map[string]string{"b.php": "<?php echo 1;", "c.php": "<?php echo 1;"})
		staged := filepath.Join(stagedTree(t, map[string]string{"a.php": "<?php echo 1;"}), "a.php")
		path := filepath.Join(dir, "a.php")
		ev := placementOf(t, staged, writerPID)
		ev.Path = path
		fm.recoverDroppedPlacement(ev)
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		var scanned []string
		fileAnalyzer = func(_ *FileMonitor, event fileEvent) {
			scanned = append(scanned, filepath.Base(event.path))
			if len(scanned) == 1 {
				if err := os.Rename(staged, path); err != nil {
					t.Fatal(err)
				}
				time.Sleep(reconcileBudget)
			}
		}
		fm.reconcileDrops()
		if !slices.Equal(scanned, []string{"b.php"}) {
			t.Fatalf("first pass scanned %v, want [b.php]", scanned)
		}
		fm.reconcileDrops()
		if want := []string{"b.php", "a.php", "b.php", "c.php"}; !slices.Equal(scanned, want) {
			t.Fatalf("resumed scan %v, want %v", scanned, want)
		}
		if got := requireReconcileQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("resumed recovery left work: %+v", got)
		}
	})
}
