//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// A directory renamed into a site raises one placement event for the
// directory and none for the files inside it, so the walk is the only
// realtime look those files get.

func placedDirTestMonitor(t *testing.T) (*FileMonitor, chan alert.Finding) {
	t.Helper()
	alerts := make(chan alert.Finding, 64)
	fm := placementTestMonitor(alerts)
	fm.analyzerCh = make(chan fileEvent, 256)
	return fm, alerts
}

// stagedTree writes files (relative path -> body) under a fresh directory
// outside the site and returns it.
func stagedTree(t *testing.T, files map[string]string) string {
	t.Helper()
	staged := filepath.Join(t.TempDir(), "staged")
	for rel, body := range files {
		path := filepath.Join(staged, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return staged
}

// placeDir renames staged into a site as name and hands the placement over.
func placeDir(t *testing.T, fm *FileMonitor, staged, name string) string {
	t.Helper()
	site := filepath.Join(t.TempDir(), "public_html")
	if err := os.Mkdir(site, 0o755); err != nil {
		t.Fatal(err)
	}
	placed := filepath.Join(site, name)
	if err := os.Rename(staged, placed); err != nil {
		t.Fatal(err)
	}
	fm.handlePlacement(placementOf(t, placed, writerPID))
	return placed
}

func walkAllPlacedDirs(fm *FileMonitor) {
	for fm.walkNextPlacedDir() {
	}
}

func walkedPaths(t *testing.T, fm *FileMonitor) []string {
	t.Helper()
	var out []string
	for _, ev := range queuedPlacements(t, fm) {
		if ev.mask&eventPlacedIn == 0 || ev.pid != writerPID {
			t.Fatalf("walked %s with mask %#x pid %d, want a placement from pid %d", ev.path, ev.mask, ev.pid, writerPID)
		}
		out = append(out, ev.path)
	}
	return out
}

func incompleteDirFindings(found []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range found {
		if f.Check == "placed_dir_incomplete_realtime" {
			out = append(out, f)
		}
	}
	return out
}

func requirePlacedDirQueue(t *testing.T, fm *FileMonitor) queuehealth.Status {
	t.Helper()
	got, exists := (&Daemon{fileMonitor: fm}).QueueStatuses()["placement.dir_walk"]
	if !exists {
		t.Fatal("placed directory walk has no health row")
	}
	return got
}

func lowerPlacedDirLimit[T any](t *testing.T, limit *T, value T) {
	t.Helper()
	previous := *limit
	*limit = value
	t.Cleanup(func() { *limit = previous })
}

func TestPlacedDirWalkAnalyzesNestedShell(t *testing.T) {
	stubInlineQuarantine(t)
	fm, alerts := placedDirTestMonitor(t)
	staged := stagedTree(t, map[string]string{"a/b/c/s.php": `<?php system($_POST['c']);`})

	placed := placeDir(t, fm, staged, "pkg")
	walkAllPlacedDirs(fm)

	shell := filepath.Join(placed, "a", "b", "c", "s.php")
	events := queuedPlacements(t, fm)
	if len(events) != 1 || events[0].path != shell {
		t.Fatalf("walk queued %+v, want %s once", events, shell)
	}
	fm.analyzeFileSafe(events[0])
	for _, f := range drainFindings(alerts) {
		if f.FilePath == shell && f.Severity == alert.Critical {
			return
		}
	}
	t.Fatalf("nested shell %s raised no critical finding", shell)
}

func TestPlacedDirWalkSkipsSymlinks(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "shell.php"), []byte(`<?php system($_POST['c']);`), 0o644); err != nil {
		t.Fatal(err)
	}
	fm, _ := placedDirTestMonitor(t)
	staged := stagedTree(t, map[string]string{"ok.php": "<?php echo 1;"})
	for name, target := range map[string]string{
		"loop":    ".",
		"out":     outside,
		"out.php": filepath.Join(outside, "shell.php"),
	} {
		if err := os.Symlink(target, filepath.Join(staged, name)); err != nil {
			t.Fatal(err)
		}
	}

	placed := placeDir(t, fm, staged, "pkg")
	walkAllPlacedDirs(fm)

	if got := walkedPaths(t, fm); len(got) != 1 || got[0] != filepath.Join(placed, "ok.php") {
		t.Fatalf("walk queued %v, want only the regular file", got)
	}
}

func TestPlacedDirWalkBudgetRaisesHigh(t *testing.T) {
	lowerPlacedDirLimit(t, &placedDirEntryLimit, 10)
	fm, alerts := placedDirTestMonitor(t)
	files := make(map[string]string)
	for i := 0; i < 50; i++ {
		files[filepath.Join("f", string(rune('a'+i/26))+string(rune('a'+i%26))+".php")] = "<?php echo 1;"
	}
	staged := stagedTree(t, files)

	placed := placeDir(t, fm, staged, "pkg")
	walkAllPlacedDirs(fm)

	// The subdirectory is one of the ten entries.
	if got := walkedPaths(t, fm); len(got) != 9 {
		t.Fatalf("walk queued %d files, want 9 within a 10-entry budget", len(got))
	}
	found := incompleteDirFindings(drainFindings(alerts))
	if len(found) != 1 || found[0].Severity != alert.High || found[0].FilePath != placed || !strings.Contains(found[0].Message, placed) {
		t.Fatalf("incomplete findings %+v, want one High naming %s", found, placed)
	}
	if fm.walkNextPlacedDir() {
		t.Fatal("a cut walk stayed queued")
	}
	if got := requirePlacedDirQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 {
		t.Fatalf("cut walk status = %+v, want one lost directory", got)
	}
}

func TestPlacedDirQueueEvictsOldest(t *testing.T) {
	lowerPlacedDirLimit(t, &placedDirQueueLimit, 2)
	fm, alerts := placedDirTestMonitor(t)
	var placed []string
	for _, name := range []string{"d0", "d1", "d2"} {
		staged := stagedTree(t, map[string]string{"x.php": "<?php echo 1;"})
		placed = append(placed, placeDir(t, fm, staged, name))
	}

	found := incompleteDirFindings(drainFindings(alerts))
	if len(found) != 1 || found[0].Severity != alert.High || found[0].FilePath != placed[0] {
		t.Fatalf("incomplete findings %+v, want one High for the oldest %s", found, placed[0])
	}
	if got := requirePlacedDirQueue(t, fm); got.Depth != 2 || got.DroppedTotal != 1 {
		t.Fatalf("queue status after eviction = %+v, want two waiting and one lost", got)
	}
	walkAllPlacedDirs(fm)
	want := []string{filepath.Join(placed[1], "x.php"), filepath.Join(placed[2], "x.php")}
	if got := walkedPaths(t, fm); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("walk queued %v, want %v", got, want)
	}
}

func TestPlacedDirWalkResumes(t *testing.T) {
	// Every pass runs out of time after its first entry.
	lowerPlacedDirLimit(t, &placedDirTimeLimit, 0)
	fm, alerts := placedDirTestMonitor(t)
	// "a-b.php" sorts between "a" and "a/x.php" as strings, not as a walk.
	staged := stagedTree(t, map[string]string{
		"a/x.php":   "<?php echo 1;",
		"a-b.php":   "<?php echo 2;",
		"b/c/y.php": "<?php echo 3;",
		"z.php":     "<?php echo 4;",
	})

	placed := placeDir(t, fm, staged, "pkg")
	seen := make(map[string]bool)
	passes := 0
	for fm.walkNextPlacedDir() {
		passes++
		got := walkedPaths(t, fm)
		if passes == 1 && len(got) == 4 {
			t.Fatal("first pass finished the directory despite its spent time budget")
		}
		for _, path := range got {
			if seen[path] {
				t.Fatalf("pass %d analyzed %s again", passes, path)
			}
			seen[path] = true
		}
	}
	for _, rel := range []string{"a/x.php", "a-b.php", "b/c/y.php", "z.php"} {
		if !seen[filepath.Join(placed, rel)] {
			t.Fatalf("resumed walk never reached %s (saw %v)", rel, seen)
		}
	}
	if found := incompleteDirFindings(drainFindings(alerts)); len(found) != 0 {
		t.Fatalf("yielding walk raised %+v", found)
	}
	if got := requirePlacedDirQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
		t.Fatalf("finished walk status = %+v", got)
	}
}

func TestPlacedDirWalkStopsOnShutdown(t *testing.T) {
	fm, _ := placedDirTestMonitor(t)
	staged := stagedTree(t, map[string]string{"x.php": "<?php echo 1;"})
	placeDir(t, fm, staged, "pkg")

	close(fm.stopCh)
	if fm.walkNextPlacedDir() {
		t.Fatal("walk ran after the monitor stopped")
	}
	if got := queuedPlacements(t, fm); len(got) != 0 {
		t.Fatalf("stopped walk queued %d files", len(got))
	}
	fm.drainAndClose()
	if got := requirePlacedDirQueue(t, fm); got.Depth != 0 || got.DroppedTotal != 1 {
		t.Fatalf("shutdown status = %+v, want the waiting directory counted lost", got)
	}
}

// fillAnalyzerQueue stands in for live events already waiting for analysis.
func fillAnalyzerQueue(fm *FileMonitor) {
	for len(fm.analyzerCh) < cap(fm.analyzerCh) {
		fm.analyzerCh <- fileEvent{path: "live", fd: -1}
	}
}

// A walk that admits faster than the analyzers drain overflows into
// per-directory recovery, which has its own cap. Pacing keeps every walked
// file on the analyzer queue.
func TestPlacedDirWalkWaitsForAnalyzerHeadroom(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lowerPlacedDirLimit(t, &placedDirTimeLimit, time.Second)
		fm := placementTestMonitor(make(chan alert.Finding, 64))
		files := make(map[string]string)
		for i := 0; i < 20; i++ {
			files[fmt.Sprintf("d%02d/x.php", i)] = "<?php echo 1;"
		}
		placed := placeDir(t, fm, stagedTree(t, files), "pkg")
		fillAnalyzerQueue(fm)

		done := make(chan struct{})
		walked := make(map[string]int)
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			for {
				select {
				case <-done:
					return
				case <-time.After(100 * time.Millisecond):
				}
				select {
				case ev := <-fm.analyzerCh:
					if ev.fd >= 0 {
						walked[ev.path]++
						_ = unix.Close(ev.fd)
					}
				default:
				}
			}
		}()
		passes := 0
		for fm.walkNextPlacedDir() {
			passes++
		}
		synctest.Wait()
		for len(fm.analyzerCh) > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		close(done)
		<-drained

		if passes < 2 {
			t.Fatalf("walk finished in %d pass, want the paced walk to span passes", passes)
		}
		for i := 0; i < 20; i++ {
			path := filepath.Join(placed, fmt.Sprintf("d%02d", i), "x.php")
			if walked[path] != 1 {
				t.Fatalf("%s reached the analyzers %d times, want once", path, walked[path])
			}
		}
		if got := fm.EventStats(); got.Dropped != 0 || len(fm.reconcileDirs) != 0 {
			t.Fatalf("walked files overflowed into recovery: dropped=%d recovery=%d", got.Dropped, len(fm.reconcileDirs))
		}
	})
}

func TestPlacedDirWalkWithoutHeadroomRaisesHigh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lowerPlacedDirLimit(t, &placedDirTimeLimit, time.Second)
		fm, alerts := placedDirTestMonitor(t)
		placed := placeDir(t, fm, stagedTree(t, map[string]string{"x.php": "<?php echo 1;"}), "pkg")
		fillAnalyzerQueue(fm)

		walkAllPlacedDirs(fm)

		if got := len(fm.analyzerCh); got != cap(fm.analyzerCh) {
			t.Fatalf("analyzer queue holds %d events, want only the %d live ones", got, cap(fm.analyzerCh))
		}
		found := incompleteDirFindings(drainFindings(alerts))
		if len(found) != 1 || found[0].Severity != alert.High || found[0].FilePath != placed {
			t.Fatalf("incomplete findings %+v, want one High for %s", found, placed)
		}
		if fm.EventStats().Dropped != 0 || len(fm.reconcileDirs) != 0 {
			t.Fatal("walk without headroom overflowed into recovery")
		}
	})
}

// Restore detection's PID-reuse guard compares the writer's start time with
// the event time. The walk runs later than the rename, so a process that
// took the renamer's PID meanwhile must not pass as the writer.
func TestPlacedDirWalkKeepsPlacementTime(t *testing.T) {
	fm, _ := placedDirTestMonitor(t)
	staged := stagedTree(t, map[string]string{"x.php": "<?php echo 1;"})
	site := filepath.Join(t.TempDir(), "public_html")
	if err := os.Mkdir(site, 0o755); err != nil {
		t.Fatal(err)
	}
	placed := filepath.Join(site, "pkg")
	if err := os.Rename(staged, placed); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(placed, "x.php")
	stubRemovedFileAt(t, map[string]checks.RemovedFile{file: removalOf(file, "<?php echo 1;", 1)})
	var chainAt []time.Time
	prev := restoreWriterChain
	restoreWriterChain = func(_ int, writtenAt time.Time) []int {
		chainAt = append(chainAt, writtenAt)
		return nil
	}
	t.Cleanup(func() { restoreWriterChain = prev })
	ev := placementOf(t, placed, writerPID)
	ev.At = time.Now().Add(-time.Hour)

	fm.handlePlacement(ev)
	walkAllPlacedDirs(fm)

	events := queuedPlacements(t, fm)
	if len(events) != 1 || !events[0].at.Equal(ev.At) {
		t.Fatalf("walked events %+v, want one stamped with the placement time %v", events, ev.At)
	}
	if len(chainAt) != 1 || !chainAt[0].Equal(ev.At) {
		t.Fatalf("writer chain resolved at %v, want the placement time %v", chainAt, ev.At)
	}
}

func TestPlacedDirWalkBoundsListing(t *testing.T) {
	lowerPlacedDirLimit(t, &placedDirEntryLimit, 10)
	read := 0
	prev := placedDirReadNames
	placedDirReadNames = func(dir *os.File, n int) ([]string, error) {
		names, err := prev(dir, n)
		read += len(names)
		return names, err
	}
	t.Cleanup(func() { placedDirReadNames = prev })
	fm, alerts := placedDirTestMonitor(t)
	files := make(map[string]string)
	for i := 0; i < 2000; i++ {
		files[fmt.Sprintf("f%04d.txt", i)] = ""
	}
	placed := placeDir(t, fm, stagedTree(t, files), "pkg")

	walkAllPlacedDirs(fm)

	if bound := 10 + 1 + placedDirReadBatch; read > bound {
		t.Fatalf("walk read %d names with a 10-entry budget, want at most %d", read, bound)
	}
	found := incompleteDirFindings(drainFindings(alerts))
	if len(found) != 1 || found[0].FilePath != placed {
		t.Fatalf("incomplete findings %+v, want one High for %s", found, placed)
	}
}

// An over-budget listing holds a readdir-order subset, so a resumed pass
// cannot see the unread names below its cursor. Deleting the names past the
// cursor must not let the walk end as complete.
func TestPlacedDirWalkOverflowStaysCut(t *testing.T) {
	lowerPlacedDirLimit(t, &placedDirEntryLimit, 10)
	lowerPlacedDirLimit(t, &placedDirTimeLimit, 0)
	fm, alerts := placedDirTestMonitor(t)
	files := make(map[string]string)
	for i := 0; i < 30; i++ {
		files[fmt.Sprintf("f%02d.txt", i)] = ""
	}
	placed := placeDir(t, fm, stagedTree(t, files), "pkg")

	if !fm.walkNextPlacedDir() {
		t.Fatal("no walk queued")
	}
	fm.placedDirMu.Lock()
	cursor := fm.placedDirs[0].cursor
	fm.placedDirMu.Unlock()
	if len(cursor) != 1 {
		t.Fatalf("first pass left cursor %v, want one name", cursor)
	}
	for name := range files {
		if name > cursor[0] {
			if err := os.Remove(filepath.Join(placed, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	walkAllPlacedDirs(fm)

	found := incompleteDirFindings(drainFindings(alerts))
	if len(found) != 1 || found[0].FilePath != placed {
		t.Fatalf("incomplete findings %+v, want one High for %s", found, placed)
	}
}

// Visiting directories is no progress for files starved of analyzer room.
func TestPlacedDirWalkStarvedPassRaisesHigh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lowerPlacedDirLimit(t, &placedDirTimeLimit, time.Second)
		fm, alerts := placedDirTestMonitor(t)
		placed := placeDir(t, fm, stagedTree(t, map[string]string{"a/b/c/x.php": "<?php echo 1;"}), "pkg")
		fillAnalyzerQueue(fm)

		// One pass: it visits a, b and c but admits no file.
		if !fm.walkNextPlacedDir() {
			t.Fatal("no walk queued")
		}

		found := incompleteDirFindings(drainFindings(alerts))
		if len(found) != 1 || found[0].FilePath != placed {
			t.Fatalf("incomplete findings %+v, want one High for %s after the starved pass", found, placed)
		}
		if fm.walkNextPlacedDir() {
			t.Fatal("starved walk stayed queued")
		}
	})
}

// Listing time is not evidence that the analyzers were busy for a pass.
func TestPlacedDirWalkResumesAfterBriefHeadroomWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lowerPlacedDirLimit(t, &placedDirTimeLimit, time.Second)
		fm, alerts := placedDirTestMonitor(t)
		placed := placeDir(t, fm, stagedTree(t, map[string]string{"x.php": "<?php echo 1;"}), "pkg")
		fillAnalyzerQueue(fm)
		previous := placedDirReadNames
		slow := true
		placedDirReadNames = func(dir *os.File, n int) ([]string, error) {
			if slow {
				slow = false
				time.Sleep(3 * time.Second / 4)
			}
			return previous(dir, n)
		}
		t.Cleanup(func() { placedDirReadNames = previous })

		if !fm.walkNextPlacedDir() {
			t.Fatal("no walk queued")
		}
		if found := incompleteDirFindings(drainFindings(alerts)); len(found) != 0 {
			t.Fatalf("brief headroom wait abandoned the walk: %+v", found)
		}
		for len(fm.analyzerCh) > 0 {
			<-fm.analyzerCh
		}
		walkAllPlacedDirs(fm)
		if got := walkedPaths(t, fm); len(got) != 1 || got[0] != filepath.Join(placed, "x.php") {
			t.Fatalf("resumed walk queued %v, want the placed file once", got)
		}
		if got := requirePlacedDirQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("resumed walk status = %+v", got)
		}
	})
}

// Slow listings must not let sustained analyzer congestion retry forever.
func TestPlacedDirWalkHeadroomWaitSpansPasses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lowerPlacedDirLimit(t, &placedDirTimeLimit, time.Second)
		fm, alerts := placedDirTestMonitor(t)
		placed := placeDir(t, fm, stagedTree(t, map[string]string{"x.php": "<?php echo 1;"}), "pkg")
		fillAnalyzerQueue(fm)
		previous := placedDirReadNames
		placedDirReadNames = func(dir *os.File, n int) ([]string, error) {
			names, err := previous(dir, n)
			if len(names) > 0 {
				time.Sleep(3 * time.Second / 4)
			}
			return names, err
		}
		t.Cleanup(func() { placedDirReadNames = previous })

		for pass := 1; pass <= 4; pass++ {
			if !fm.walkNextPlacedDir() {
				t.Fatalf("walk ended before pass %d", pass)
			}
			found := incompleteDirFindings(drainFindings(alerts))
			if pass < 4 {
				if len(found) != 0 {
					t.Fatalf("pass %d counted listing time as analyzer starvation: %+v", pass, found)
				}
			} else if len(found) != 1 || found[0].Severity != alert.High || found[0].FilePath != placed {
				t.Fatalf("sustained congestion raised %+v, want one High for %s", found, placed)
			}
		}
		if fm.walkNextPlacedDir() {
			t.Fatal("starved walk stayed queued")
		}
	})
}

// Names before a resume cursor still cost directory I/O and must be bounded.
func TestPlacedDirWalkBoundsListingBeforeCursor(t *testing.T) {
	lowerPlacedDirLimit(t, &placedDirEntryLimit, 10)
	fm, alerts := placedDirTestMonitor(t)
	files := map[string]string{"z.php": "<?php echo 1;"}
	for i := 0; i < 2000; i++ {
		files[fmt.Sprintf("f%04d.txt", i)] = ""
	}
	placed := placeDir(t, fm, stagedTree(t, files), "pkg")
	// The directory grew behind the cursor between walk passes.
	fm.placedDirs[0].cursor = []string{"y.php"}
	fm.placedDirs[0].entries = 1
	read := 0
	previous := placedDirReadNames
	placedDirReadNames = func(dir *os.File, n int) ([]string, error) {
		names, err := previous(dir, n)
		read += len(names)
		return names, err
	}
	t.Cleanup(func() { placedDirReadNames = previous })

	walkAllPlacedDirs(fm)
	_ = queuedPlacements(t, fm)
	if bound := placedDirEntryLimit + 1 + placedDirReadBatch; read > bound {
		t.Errorf("resumed listing read %d names, want at most %d", read, bound)
	}
	found := incompleteDirFindings(drainFindings(alerts))
	if len(found) != 1 || found[0].Severity != alert.High || found[0].FilePath != placed {
		t.Fatalf("incomplete findings %+v, want one High for %s", found, placed)
	}
}

// A listing that spends the whole pass must still allow a bounded wait for
// analyzer room; otherwise each retry repeats the I/O without advancing.
func TestPlacedDirSlowListingStillBoundsCongestion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lowerPlacedDirLimit(t, &placedDirTimeLimit, time.Second)
		fm, alerts := placedDirTestMonitor(t)
		placed := placeDir(t, fm, stagedTree(t, map[string]string{"x.php": "<?php echo 1;"}), "pkg")
		fillAnalyzerQueue(fm)
		previous := placedDirReadNames
		placedDirReadNames = func(dir *os.File, n int) ([]string, error) {
			names, err := previous(dir, n)
			if len(names) > 0 {
				time.Sleep(2 * time.Second)
			}
			return names, err
		}
		t.Cleanup(func() { placedDirReadNames = previous })

		if !fm.walkNextPlacedDir() {
			t.Fatal("no walk queued")
		}
		found := incompleteDirFindings(drainFindings(alerts))
		if len(found) != 1 || found[0].Severity != alert.High || found[0].FilePath != placed {
			t.Fatalf("slow listing left congestion unbounded: %+v", found)
		}
		if fm.walkNextPlacedDir() {
			t.Fatal("starved walk stayed queued")
		}
	})
}

func TestPlacedDirSlowListingAcceptsFreedHeadroom(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lowerPlacedDirLimit(t, &placedDirTimeLimit, time.Second)
		fm, alerts := placedDirTestMonitor(t)
		placed := placeDir(t, fm, stagedTree(t, map[string]string{"x.php": "<?php echo 1;"}), "pkg")
		fillAnalyzerQueue(fm)
		previous := placedDirReadNames
		placedDirReadNames = func(dir *os.File, n int) ([]string, error) {
			names, err := previous(dir, n)
			if len(names) > 0 {
				time.Sleep(2 * time.Second)
			}
			return names, err
		}
		t.Cleanup(func() { placedDirReadNames = previous })
		go func() {
			time.Sleep(2500 * time.Millisecond)
			for range cap(fm.analyzerCh) {
				<-fm.analyzerCh
			}
		}()

		if !fm.walkNextPlacedDir() {
			t.Fatal("no walk queued")
		}
		if got := walkedPaths(t, fm); len(got) != 1 || got[0] != filepath.Join(placed, "x.php") {
			t.Fatalf("freed headroom did not admit the placed file once: %v", got)
		}
		if found := incompleteDirFindings(drainFindings(alerts)); len(found) != 0 {
			t.Fatalf("available analyzers reported as congested: %+v", found)
		}
		if got := requirePlacedDirQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("completed walk status = %+v", got)
		}
	})
}
