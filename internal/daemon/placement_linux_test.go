//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/yara"
)

func TestPlacementRetriesOldSocket(t *testing.T) {
	dir := t.TempDir()
	staged, path := filepath.Join(dir, "staged.php"), filepath.Join(dir, "x.php")
	if err := os.WriteFile(staged, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	ev := placementOf(t, staged, 0)
	fd, _, retry, err := openPlacedOnce(path, ev.Dev, ev.Ino)
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	if err == nil || !retry || fd != -1 {
		t.Fatalf("old socket: fd=%d retry=%v err=%v, want retry without a descriptor", fd, retry, err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatal(err)
	}
	ev.Path = path
	fm := placementTestMonitor(make(chan alert.Finding, 4))
	fm.handlePlacement(ev)
	if events := queuedPlacements(t, fm); len(events) != 1 || events[0].path != path {
		t.Fatalf("queued %+v, want the replacement once", events)
	}
}

// Even a nonblocking read-open of a FIFO changes what another process sees.
// Inspecting an unverified entry must not open it for I/O.
func TestPlacementDoesNotReadOpenSpecialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.php")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	ev := placementOf(t, path, 0)
	watch, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(watch) }()
	if _, err = unix.InotifyAddWatch(watch, path, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	fd, _, retry, err := openPlacedOnce(path, ev.Dev, ev.Ino)
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	if err == nil || retry || fd != -1 {
		t.Fatalf("FIFO: fd=%d retry=%v err=%v, want final rejection", fd, retry, err)
	}
	var buf [4096]byte
	if n, err := unix.Read(watch, buf[:]); n > 0 || !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("FIFO was opened for I/O: inotify read n=%d err=%v", n, err)
	}
}

func TestPlacementOverflowRecoversOldFiles(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		t.Run(fmt.Sprint("refresh=", refresh), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "x.php")
			if err := os.WriteFile(path, []byte("<?php echo 1;"), 0o600); err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-24 * time.Hour)
			if err := os.Chtimes(path, old, old); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path, filepath.Join(filepath.Dir(path), "link.php")); err != nil {
				t.Fatal(err)
			}
			fm := placementTestMonitor(make(chan alert.Finding, 4))
			fm.analyzerCh = make(chan fileEvent)
			fm.handlePlacement(placementOf(t, path, 0))
			if got := fm.EventStats(); got.Dropped != 1 {
				t.Fatalf("stats = %+v, want one dropped placement", got)
			}
			if refresh {
				fm.recordDroppedDir(path)
			}
			previous := fileAnalyzer
			t.Cleanup(func() { fileAnalyzer = previous })
			var scanned []string
			fileAnalyzer = func(_ *FileMonitor, event fileEvent) {
				scanned = append(scanned, event.path)
			}
			fm.reconcileDrops()
			if !reflect.DeepEqual(scanned, []string{path}) {
				t.Fatalf("recovered %v, want the old placed file", scanned)
			}
		})
	}
}

func TestPlacementRecoverySurvivesConcurrentDropAndYield(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		paths := []string{filepath.Join(dir, "a.php"), filepath.Join(dir, "b.php")}
		for _, path := range paths {
			if err := os.WriteFile(path, []byte("<?php echo 1;"), 0o600); err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-24 * time.Hour)
			if err := os.Chtimes(path, old, old); err != nil {
				t.Fatal(err)
			}
		}
		fm := placementTestMonitor(make(chan alert.Finding, 4))
		fm.analyzerCh = make(chan fileEvent)
		fm.handlePlacement(placementOf(t, paths[0], 0))
		previous := fileAnalyzer
		defer func() { fileAnalyzer = previous }()
		var scanned []string
		fileAnalyzer = func(_ *FileMonitor, event fileEvent) {
			scanned = append(scanned, event.path)
			if len(scanned) == 1 {
				// A write arrives while the placement recovery owns the old batch.
				fm.recordDroppedDir(paths[1])
				time.Sleep(reconcileBudget)
			}
		}
		fm.reconcileDrops()
		if !reflect.DeepEqual(scanned, paths[:1]) {
			t.Fatalf("first pass scanned %v, want only %s", scanned, paths[0])
		}
		fm.reconcileDrops()
		want := []string{paths[0], paths[0], paths[1]}
		if !reflect.DeepEqual(scanned, want) {
			t.Fatalf("resumed recovery scanned %v, want %v", scanned, want)
		}
		if got := requireReconcileQueue(t, fm); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
			t.Fatalf("completed recovery status = %+v", got)
		}
	})
}

// A file renamed or linked into a site raises no close-write, so the
// placement backends report it and handlePlacement must give it the same
// analysis and response a write in place gets.

func placementTestMonitor(alerts chan alert.Finding) *FileMonitor {
	fm := shutdownDrainTestMonitor(8)
	fm.alertCh = alerts
	fm.recent = newRecentAnalyses(recentAnalysisCap, recentAnalysisTTL)
	return fm
}

// analyzeClosedWrite runs path through close-write admission and a completed
// analysis, the way the analyzer worker does.
func analyzeClosedWrite(t *testing.T, fm *FileMonitor, path string) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	fm.handleEvent(fd, 0, unix.FAN_CLOSE_WRITE)
	events := queuedPlacements(t, fm)
	if len(events) != 1 {
		t.Fatalf("close-write of %s queued %d events, want 1", path, len(events))
	}
	fm.analyzeFileSafe(events[0])
}

// stubInlineQuarantine keeps confirmed PHP findings from moving test files.
func stubInlineQuarantine(t *testing.T) {
	t.Helper()
	prev := inlineQuarantineConfirmedPHP
	inlineQuarantineConfirmedPHP = func(_ *config.Config, finding *alert.Finding, _ string, _ []byte, _ os.FileInfo, _ int) (string, bool, *alert.Finding) {
		finding.AutoFileResponseEvaluated = true
		return "", false, nil
	}
	t.Cleanup(func() { inlineQuarantineConfirmedPHP = prev })
}

func hasFinding(found []alert.Finding, check, path string) bool {
	for _, f := range found {
		if f.Check == check && f.FilePath == path {
			return true
		}
	}
	return false
}

// placeAndAnalyze renames from to to, hands the placement over and analyses
// whatever it queued. It returns the number of events queued.
func placeAndAnalyze(t *testing.T, fm *FileMonitor, from, to string, pid int32) int {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
	fm.handlePlacement(placementOf(t, to, pid))
	events := queuedPlacements(t, fm)
	for _, ev := range events {
		fm.analyzeFileSafe(ev)
	}
	return len(events)
}

// cPanel's file transfer writes .temp.<n>.<name> and renames it into place.
// The bytes, inode and analysis are the same, so the placement is not
// analysed a second time.
func TestPlacementSkipsUnchangedRenameWithinClass(t *testing.T) {
	dir := t.TempDir()
	staged, path := filepath.Join(dir, ".temp.1731400000123.x.php"), filepath.Join(dir, "x.php")
	if err := os.WriteFile(staged, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	fm := placementTestMonitor(make(chan alert.Finding, 16))
	analyzeClosedWrite(t, fm, staged)
	before := fm.EventStats()

	if n := placeAndAnalyze(t, fm, staged, path, 0); n != 0 {
		t.Fatalf("unchanged rename queued %d events, want none", n)
	}
	if after := fm.EventStats(); after.Received != before.Received || after.PlacementSkipped != before.PlacementSkipped+1 {
		t.Fatalf("stats %+v -> %+v, want one skip and no admission decision", before, after)
	}
}

// recordedPlacement analyses a cPanel staged write and returns the paths for
// its rename. The skip test above shows the rename alone is not analysed.
func recordedPlacement(t *testing.T, fm *FileMonitor, dir, name, body string) (staged, path string) {
	t.Helper()
	staged, path = filepath.Join(dir, ".temp.1731400000123."+name), filepath.Join(dir, name)
	if err := os.WriteFile(staged, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	analyzeClosedWrite(t, fm, staged)
	return staged, path
}

// placementDropperMonitor is a placement test monitor that also tracks
// self-deleting droppers under dir, capturing their findings.
func placementDropperMonitor(t *testing.T, dir string, ttl time.Duration, alerts chan alert.Finding) (*FileMonitor, *[]capturedAlert) {
	t.Helper()
	fm := placementTestMonitor(alerts)
	fm.dropper = newDropperEngine(dropperEngineConfig{ttl: ttl, selfPID: 99999})
	fm.dropperQuarantines = newDropperQuarantineLedger(ttl + time.Minute)
	fm.setDropperDocroots([]string{dir})
	var got []capturedAlert
	fm.dropper.emit = func(sev alert.Severity, check, msg, details, path, _ string) {
		got = append(got, capturedAlert{sev: sev, check: check, msg: msg, details: details, path: path})
	}
	return fm, &got
}

// analyzeWriteBy runs path through close-write admission from pid and a
// completed analysis.
func analyzeWriteBy(t *testing.T, fm *FileMonitor, path string, pid int32) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	fm.handleEvent(fd, pid, unix.FAN_CLOSE_WRITE)
	events := queuedPlacements(t, fm)
	if len(events) != 1 {
		t.Fatalf("close-write of %s queued %d events, want 1", path, len(events))
	}
	fm.analyzeFileSafe(events[0])
}

// The deletion probe looks at the path a candidate was tracked at. A skipped
// placement is still a new path for a file that may delete itself there.
func TestPlacementSkippedFileTrackedAsDropper(t *testing.T) {
	const ttl = time.Minute
	dir := t.TempDir()
	fm, got := placementDropperMonitor(t, dir, ttl, make(chan alert.Finding, 16))
	staged, path := filepath.Join(dir, ".temp.1731400000123.x.php"), filepath.Join(dir, "x.php")
	if err := os.WriteFile(staged, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	analyzeWriteBy(t, fm, staged, writerPID)

	if n := placeAndAnalyze(t, fm, staged, path, writerPID); n != 0 {
		t.Fatalf("unchanged rename queued %d events, want the skip", n)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	probeAt := time.Now().Add(ttl + time.Second)
	prober := fm.newDropperFSProbe()
	fm.dropper.probeStep(probeAt, prober, probeAt)
	flushAt := probeAt.Add(dropperGraceWindow + time.Second)
	fm.dropper.probeStep(flushAt, prober, flushAt)

	for _, a := range *got {
		if a.check == dropperCheckName && a.path == path {
			return
		}
	}
	t.Fatalf("dropper findings %+v, want a self-delete of %s", *got, path)
}

// Suspicious content below the quarantine bar keeps its file under
// watch. The placed path gets the full analysis, so its dropper candidate
// carries the verdict the no-skip path gives it.
func TestPlacementSuspiciousFileIsAnalyzed(t *testing.T) {
	useRealtimeRules(t, realtimeHighRule)
	const ttl = time.Minute
	dir := t.TempDir()
	alerts := make(chan alert.Finding, 16)
	fm, _ := placementDropperMonitor(t, dir, ttl, alerts)
	staged, path := filepath.Join(dir, ".temp.1731400000123.x.php"), filepath.Join(dir, "x.php")
	if err := os.WriteFile(staged, []byte("<?php echo 'EVIL_MARKER_A';"), 0o644); err != nil {
		t.Fatal(err)
	}
	analyzeWriteBy(t, fm, staged, writerPID)
	if found := drainChecks(alerts); found["signature_match_realtime"] != alert.High {
		t.Fatalf("staged write findings %v, want one High signature match", found)
	}

	if n := placeAndAnalyze(t, fm, staged, path, writerPID); n != 1 {
		t.Fatalf("suspicious file's rename queued %d events, want 1", n)
	}
	for _, c := range fm.dropper.tr.Due(time.Now().Add(ttl + time.Second)) {
		if c.Path == path {
			if !c.ContentSuspicious {
				t.Fatalf("candidate for %s lost the suspicious verdict", path)
			}
			return
		}
	}
	t.Fatalf("no dropper candidate for %s", path)
}

// chmod raises no event and keeps mtime, but the analysis branches on mode.
func TestPlacementModeChangeIsAnalyzed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".config")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	staged, path := recordedPlacement(t, fm, dir, "m", "#!/bin/sh\n")
	if found := drainFindings(alerts); len(found) != 0 {
		t.Fatalf("non-executable staged file raised %+v", found)
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		t.Fatal(err)
	}

	if n := placeAndAnalyze(t, fm, staged, path, 0); n != 1 {
		t.Fatalf("rename after chmod +x queued %d events, want 1", n)
	}
	if found := drainFindings(alerts); !hasFinding(found, "executable_in_config_realtime", path) {
		t.Fatalf("findings %+v, want the executable finding on %s", found, path)
	}
}

// A file analysed clean, rewritten under a name admission ignores with its
// size and mtime put back, then renamed back, is a different file.
func TestPlacementReplayThroughAliasIsAnalyzed(t *testing.T) {
	dir := t.TempDir()
	shell := `<?php system($_POST['c']);`
	benign := "<?php echo 1;" + strings.Repeat(" ", len(shell)-len("<?php echo 1;"))
	path, alias := filepath.Join(dir, "x.php"), filepath.Join(dir, "x.txt")
	if err := os.WriteFile(path, []byte(benign), 0o644); err != nil {
		t.Fatal(err)
	}
	stubInlineQuarantine(t)
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	analyzeClosedWrite(t, fm, path)
	var analysed unix.Stat_t
	if err := unix.Stat(path, &analysed); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, alias); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(alias, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Pwrite(fd, []byte(shell), 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, alias, []unix.Timespec{analysed.Atim, analysed.Mtim}, 0); err != nil {
		t.Fatal(err)
	}
	// The close-write under the alias is rejected at admission.
	fm.handleEvent(fd, 0, unix.FAN_CLOSE_WRITE)
	if got := queuedPlacements(t, fm); len(got) != 0 {
		t.Fatalf("alias close-write queued %d events, want admission to reject it", len(got))
	}
	var rewritten unix.Stat_t
	if err := unix.Stat(alias, &rewritten); err != nil {
		t.Fatal(err)
	}
	if rewritten.Size != analysed.Size || rewritten.Mtim != analysed.Mtim {
		t.Fatal("fixture must restore size and mtime")
	}
	drainFindings(alerts)

	if n := placeAndAnalyze(t, fm, alias, path, 0); n != 1 {
		t.Fatalf("replayed rename queued %d events, want 1", n)
	}
	if found := drainFindings(alerts); !hasFinding(found, "webshell_content_realtime", path) {
		t.Fatalf("findings %+v, want the PHP scan on %s", found, path)
	}
}

func TestPlacementRewriteBeforeWriterClosesIsAnalyzed(t *testing.T) {
	shell := `<?php system($_POST['c']);`
	benign := "<?php echo 1;" + strings.Repeat(" ", len(shell)-len("<?php echo 1;"))
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	staged, path := recordedPlacement(t, fm, t.TempDir(), "x.php", benign)
	stubInlineQuarantine(t)
	var before unix.Stat_t
	if err := unix.Stat(staged, &before); err != nil {
		t.Fatal(err)
	}
	writer, err := unix.Open(staged, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(writer) }()
	if _, err := unix.Pwrite(writer, []byte(shell), 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, staged, []unix.Timespec{before.Atim, before.Mtim}, 0); err != nil {
		t.Fatal(err)
	}
	// No close-write can invalidate the old verdict while writer stays open.
	if n := placeAndAnalyze(t, fm, staged, path, 0); n != 1 {
		t.Fatalf("rewritten placement queued %d events, want 1", n)
	}
	if found := drainFindings(alerts); !hasFinding(found, "webshell_content_realtime", path) {
		t.Fatalf("findings %+v, want the rewritten shell detected", found)
	}
}

func TestPlacementAfterFailedScanIsAnalyzed(t *testing.T) {
	backend := &snapshotBackend{t: t, scanErr: errors.New("worker unavailable")}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	staged, path := recordedPlacement(t, fm, t.TempDir(), "x.php", "<?php include 'original.png';")
	if found := drainFindings(alerts); !hasFinding(found, "yara_realtime_scan_error", "") {
		t.Fatalf("findings %+v, want the scanner error", found)
	}
	// Recovery of the same backend need not publish a new rules generation.
	backend.scanErr = nil
	if n := placeAndAnalyze(t, fm, staged, path, 0); n != 1 {
		t.Fatalf("placement after scan failure queued %d events, want 1", n)
	}
	if found := drainFindings(alerts); !hasFinding(found, "yara_match_realtime", path) {
		t.Fatalf("findings %+v, want the recovered scanner's verdict", found)
	}
}

func TestPlacementConfigFindingIsNotCachedAsClean(t *testing.T) {
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	staged, path := recordedPlacement(t, fm, t.TempDir(), ".user.ini", "allow_url_include = On\n")
	if found := drainFindings(alerts); !hasFinding(found, "php_config_realtime", staged) {
		t.Fatalf("findings %+v, want the staged configuration finding", found)
	}
	if n := placeAndAnalyze(t, fm, staged, path, 0); n != 1 {
		t.Fatalf("suspicious configuration placement queued %d events, want 1", n)
	}
	if found := drainFindings(alerts); !hasFinding(found, "php_config_realtime", path) {
		t.Fatalf("findings %+v, want the installed configuration finding", found)
	}
}

func TestPlacementReadFailureIsNotCachedAsClean(t *testing.T) {
	dir := t.TempDir()
	staged, path := filepath.Join(dir, ".temp.1731400000123.x.php"), filepath.Join(dir, "x.php")
	if err := os.WriteFile(staged, []byte(`<?php system($_POST['c']);`), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(staged, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	stubInlineQuarantine(t)
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	// Metadata is readable, but the content read fails on this descriptor.
	fm.analyzeFileSafe(fileEvent{path: staged, fd: fd})
	if n := placeAndAnalyze(t, fm, staged, path, 0); n != 1 {
		t.Fatalf("placement after read failure queued %d events, want 1", n)
	}
	if found := drainFindings(alerts); !hasFinding(found, "webshell_content_realtime", path) {
		t.Fatalf("findings %+v, want a successful content scan", found)
	}
}

func TestPlacementMutationDuringAnalysisIsNotCached(t *testing.T) {
	dir := t.TempDir()
	staged, path := filepath.Join(dir, ".temp.1731400000123.x.php"), filepath.Join(dir, "x.php")
	shell := `<?php system($_POST['c']);`
	benign := "<?php echo 1;" + strings.Repeat(" ", len(shell)-len("<?php echo 1;"))
	if err := os.WriteFile(staged, []byte(shell), 0o600); err != nil {
		t.Fatal(err)
	}
	var before unix.Stat_t
	if err := unix.Stat(staged, &before); err != nil {
		t.Fatal(err)
	}
	rewrite := func(body string) {
		t.Helper()
		if err := os.WriteFile(staged, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := unix.UtimesNanoAt(unix.AT_FDCWD, staged, []unix.Timespec{before.Atim, before.Mtim}, 0); err != nil {
			t.Fatal(err)
		}
	}
	previous := fileAnalyzer
	t.Cleanup(func() { fileAnalyzer = previous })
	fileAnalyzer = func(fm *FileMonitor, event fileEvent) {
		rewrite(benign)
		previous(fm, event)
		rewrite(shell)
	}
	stubInlineQuarantine(t)
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	analyzeClosedWrite(t, fm, staged)
	fileAnalyzer = previous
	if found := drainFindings(alerts); len(found) != 0 {
		t.Fatalf("fixture should scan clean intermediate bytes, got %+v", found)
	}
	if n := placeAndAnalyze(t, fm, staged, path, 0); n != 1 {
		t.Fatalf("placement after mutation queued %d events, want 1", n)
	}
	if found := drainFindings(alerts); !hasFinding(found, "webshell_content_realtime", path) {
		t.Fatalf("findings %+v, want the restored malicious bytes scanned", found)
	}
}

// Writes the kernel dropped carry no descriptor, so no inode can be
// forgotten selectively.
func TestPlacementAfterQueueOverflowIsAnalyzed(t *testing.T) {
	fm := placementTestMonitor(make(chan alert.Finding, 16))
	staged, path := recordedPlacement(t, fm, t.TempDir(), "x.php", "<?php echo 1;")
	fm.handleQueueOverflow()

	if n := placeAndAnalyze(t, fm, staged, path, 0); n != 1 {
		t.Fatalf("rename after a kernel overflow queued %d events, want 1", n)
	}
}

// A file analysed clean under the old rules or settings says nothing about
// the new ones.
func TestPlacementAfterReloadIsAnalyzed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reload func(t *testing.T, fm *FileMonitor)
	}{
		{"config", func(t *testing.T, fm *FileMonitor) {
			previous := config.Active()
			t.Cleanup(func() { config.SetActive(previous) })
			config.SetActive(fm.cfg)
		}},
		{"signatures", func(t *testing.T, _ *FileMonitor) {
			previous := signatures.SetGlobal(signatures.NewScanner(t.TempDir()))
			t.Cleanup(func() { signatures.SetGlobal(previous) })
		}},
		{"yara", func(*testing.T, *FileMonitor) { yara.InvalidateCaches() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fm := placementTestMonitor(make(chan alert.Finding, 16))
			staged, path := recordedPlacement(t, fm, t.TempDir(), "x.php", "<?php echo 1;")
			tc.reload(t, fm)

			if n := placeAndAnalyze(t, fm, staged, path, 0); n != 1 {
				t.Fatalf("rename after a %s reload queued %d events, want 1", tc.name, n)
			}
		})
	}
}

func TestPlacementExtensionChangeIsAnalyzed(t *testing.T) {
	// A credential log name is admitted anywhere, so the text file gets a
	// full analysis under the text rules first.
	dir := eventFilterDir(t)
	staged, path := filepath.Join(dir, "results.txt"), filepath.Join(dir, "results.php")
	if err := os.WriteFile(staged, []byte(`<?php system($_POST['c']);`), 0o644); err != nil {
		t.Fatal(err)
	}
	stubInlineQuarantine(t)
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	analyzeClosedWrite(t, fm, staged)
	if found := drainFindings(alerts); hasFinding(found, "webshell_content_realtime", staged) {
		t.Fatalf("results.txt already raised the PHP finding: %+v", found)
	}

	if n := placeAndAnalyze(t, fm, staged, path, 0); n != 1 {
		t.Fatalf("extension change queued %d events, want 1", n)
	}
	if found := drainFindings(alerts); !hasFinding(found, "webshell_content_realtime", path) {
		t.Fatalf("findings %+v, want the PHP scan on %s", found, path)
	}
}

// A shell uploaded as HTML passes the phishing check; renamed to PHP it
// must meet the PHP scanner.
func TestPlacementHTMLToPHPIsAnalyzed(t *testing.T) {
	// Not under a shared temp tree, whose admission drops plain HTML.
	docroot := filepath.Join(eventFilterDir(t), "public_html")
	if err := os.Mkdir(docroot, 0o755); err != nil {
		t.Fatal(err)
	}
	staged, path := filepath.Join(docroot, "a.html"), filepath.Join(docroot, "a.php")
	if err := os.WriteFile(staged, []byte(`<?php system($_POST['c']);`), 0o644); err != nil {
		t.Fatal(err)
	}
	stubInlineQuarantine(t)
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	fm.docRootPatterns = []string{docroot}
	analyzeClosedWrite(t, fm, staged)
	if found := drainFindings(alerts); hasFinding(found, "webshell_content_realtime", staged) {
		t.Fatalf("a.html already raised the PHP finding: %+v", found)
	}

	if n := placeAndAnalyze(t, fm, staged, path, 0); n != 1 {
		t.Fatalf("html to php rename queued %d events, want 1", n)
	}
	if found := drainFindings(alerts); !hasFinding(found, "webshell_content_realtime", path) {
		t.Fatalf("findings %+v, want the PHP scan on %s", found, path)
	}
}

func TestPlacementStagingToUploadsIsAnalyzed(t *testing.T) {
	site := t.TempDir()
	staged := filepath.Join(site, "wp-content", "upgrade", "pkg", "s.php")
	path := filepath.Join(site, "wp-content", "uploads", "s.php")
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte(`<?php system($_POST['c']);`), 0o644); err != nil {
		t.Fatal(err)
	}
	stubInlineQuarantine(t)
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	analyzeClosedWrite(t, fm, staged)
	if found := drainFindings(alerts); hasFinding(found, "php_in_uploads_realtime", staged) {
		t.Fatalf("staging analysis raised an uploads finding: %+v", found)
	}

	if n := placeAndAnalyze(t, fm, staged, path, 0); n != 1 {
		t.Fatalf("staging to uploads rename queued %d events, want 1", n)
	}
	if found := drainFindings(alerts); !hasFinding(found, "php_in_uploads_realtime", path) {
		t.Fatalf("findings %+v, want the uploads finding on %s", found, path)
	}
}

// A suppression that covered the staged name says nothing about the file
// once it leaves that name.
func TestPlacementOutOfSuppressedPathIsAnalyzed(t *testing.T) {
	dir := t.TempDir()
	staged, path := filepath.Join(dir, ".temp.1731400000123.x.php"), filepath.Join(dir, "x.php")
	if err := os.WriteFile(staged, []byte(`<?php system($_POST['c']);`), 0o644); err != nil {
		t.Fatal(err)
	}
	stubInlineQuarantine(t)
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	fm.cfg.Suppressions.IgnorePaths = []string{".temp.*"}
	analyzeClosedWrite(t, fm, staged)
	if found := drainFindings(alerts); len(found) != 0 {
		t.Fatalf("suppressed staged write raised %+v", found)
	}

	if n := placeAndAnalyze(t, fm, staged, path, 0); n != 1 {
		t.Fatalf("rename out of the suppression queued %d events, want 1", n)
	}
	if found := drainFindings(alerts); !hasFinding(found, "webshell_content_realtime", path) {
		t.Fatalf("findings %+v, want the PHP scan on %s", found, path)
	}
}

// A restore loop stages the removed payload and renames it over the old
// path. That rename is the restore, whatever was analysed before it.
func TestPlacementOverRemovedPathIsAnalyzed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.php")
	staged := filepath.Join(dir, ".temp.1731400000123.index.php")
	stubRemovedFileAt(t, map[string]checks.RemovedFile{path: removalOf(path, restoredPayload, 9)})
	if err := os.WriteFile(staged, []byte(restoredPayload), 0o644); err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	analyzeClosedWrite(t, fm, staged)
	if got := restoredFindings(drainFindings(alerts)); len(got) != 0 {
		t.Fatalf("staged copy raised %+v, want no restore before the rename", got)
	}

	if n := placeAndAnalyze(t, fm, staged, path, writerPID); n != 1 {
		t.Fatalf("rename over the removed path queued %d events, want 1", n)
	}
	if got := restoredFindings(drainFindings(alerts)); len(got) != 1 || got[0].PID != writerPID {
		t.Fatalf("restore findings = %+v, want one naming pid %d", got, writerPID)
	}
}

func placementOf(t *testing.T, path string, pid int32) placementEvent {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	return placementEvent{
		Path: path, Dev: uint64(st.Dev), Ino: st.Ino,
		PID: pid, Kind: placementRename, At: time.Now(),
	}
}

// queuedPlacements drains everything handlePlacement queued for analysis.
func queuedPlacements(t *testing.T, fm *FileMonitor) []fileEvent {
	t.Helper()
	var out []fileEvent
	for {
		select {
		case ev := <-fm.analyzerCh:
			t.Cleanup(func() { _ = unix.Close(ev.fd) })
			out = append(out, ev)
		default:
			return out
		}
	}
}

func TestPlacementRenamedShellIsQuarantined(t *testing.T) {
	docroot := filepath.Join(t.TempDir(), "public_html")
	if err := os.Mkdir(docroot, 0o755); err != nil {
		t.Fatal(err)
	}
	staged, path := filepath.Join(docroot, "x.txt"), filepath.Join(docroot, "x.php")
	if err := os.WriteFile(staged, []byte(`<?php system($_POST['c']);`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatal(err)
	}
	type response struct {
		path, procInfo string
		fd             int
	}
	var responses []response
	oldResponse := inlineQuarantineConfirmedPHP
	inlineQuarantineConfirmedPHP = func(_ *config.Config, finding *alert.Finding, p string, _ []byte, _ os.FileInfo, fd int) (string, bool, *alert.Finding) {
		responses = append(responses, response{p, finding.ProcessInfo, fd})
		finding.AutoFileResponseEvaluated = true
		return "", false, nil
	}
	t.Cleanup(func() { inlineQuarantineConfirmedPHP = oldResponse })
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	pid := int32(os.Getppid())
	wantProc := resolveProcessInfo(pid)
	if wantProc == "" {
		t.Fatal("test needs a live pid to resolve")
	}

	fm.handlePlacement(placementOf(t, path, pid))

	events := queuedPlacements(t, fm)
	if len(events) != 1 {
		t.Fatalf("queued %d events, want the placed file once", len(events))
	}
	if events[0].mask&eventPlacedIn == 0 || events[0].pid != pid {
		t.Fatalf("queued event mask=%#x pid=%d, want placed-in from pid %d", events[0].mask, events[0].pid, pid)
	}
	fm.analyzeFile(events[0])
	if len(responses) != 1 || responses[0].path != path || responses[0].fd != events[0].fd {
		t.Fatalf("inline quarantine calls = %+v, want one for %s on the event fd", responses, path)
	}
	if responses[0].procInfo != wantProc {
		t.Fatalf("finding process = %q, want %q from the event pid", responses[0].procInfo, wantProc)
	}
}

func TestPlacementNeverFollowsSymlink(t *testing.T) {
	outside, tree := t.TempDir(), t.TempDir()
	shell := filepath.Join(outside, "shell.php")
	if err := os.WriteFile(shell, []byte(`<?php system($_POST['c']);`), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tree, "x.php")
	if err := os.Symlink(shell, link); err != nil {
		t.Fatal(err)
	}
	fm := placementTestMonitor(make(chan alert.Finding, 4))

	start := time.Now()
	fm.handlePlacement(placementOf(t, link, 0))

	if got := queuedPlacements(t, fm); len(got) != 0 {
		t.Fatalf("symlink placement queued %d events, want none", len(got))
	}
	stats := fm.EventStats()
	if stats.PlacementUnverified != 1 || stats.Received != 0 {
		t.Fatalf("stats = %+v, want one unverified placement and no admission decision", stats)
	}
	// A symlink can never become the reported inode, so waiting is pointless.
	if elapsed := time.Since(start); elapsed >= 50*time.Millisecond {
		t.Fatalf("symlink placement retried for %v", elapsed)
	}
}

func TestPlacementWaitsForPendingRename(t *testing.T) {
	dir := t.TempDir()
	staged, path := filepath.Join(dir, ".x.php.part"), filepath.Join(dir, "x.php")
	if err := os.WriteFile(staged, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := placementOf(t, staged, 0)
	ev.Path = path
	fm := placementTestMonitor(make(chan alert.Finding, 4))
	renamed := make(chan error, 1)
	go func() {
		time.Sleep(30 * time.Millisecond)
		renamed <- os.Rename(staged, path)
	}()

	fm.handlePlacement(ev)

	if err := <-renamed; err != nil {
		t.Fatal(err)
	}
	events := queuedPlacements(t, fm)
	if len(events) != 1 || events[0].path != path {
		t.Fatalf("queued %+v, want %s once", events, path)
	}
	if stats := fm.EventStats(); stats.PlacementUnverified != 0 || stats.Admitted != 1 {
		t.Fatalf("stats = %+v, want one admitted and none unverified", stats)
	}
}

// The entry being replaced is the attacker's choice. An old symlink at the
// destination must not turn a pending rename into an immediate drop.
func TestPlacementWaitsForRenameOverSymlink(t *testing.T) {
	dir := t.TempDir()
	staged, path := filepath.Join(dir, ".x.php.part"), filepath.Join(dir, "x.php")
	if err := os.WriteFile(staged, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere.php"), path); err != nil {
		t.Fatal(err)
	}
	ev := placementOf(t, staged, 0)
	ev.Path = path
	fm := placementTestMonitor(make(chan alert.Finding, 4))
	renamed := make(chan error, 1)
	go func() {
		time.Sleep(30 * time.Millisecond)
		renamed <- os.Rename(staged, path)
	}()

	fm.handlePlacement(ev)

	if err := <-renamed; err != nil {
		t.Fatal(err)
	}
	events := queuedPlacements(t, fm)
	if len(events) != 1 || events[0].path != path {
		t.Fatalf("queued %+v, want %s once", events, path)
	}
	if stats := fm.EventStats(); stats.PlacementUnverified != 0 {
		t.Fatalf("stats = %+v, want none unverified", stats)
	}
}

func TestPlacementIdentityMismatchDropped(t *testing.T) {
	dir := t.TempDir()
	reported, path := filepath.Join(dir, "reported.php"), filepath.Join(dir, "x.php")
	for _, p := range []string{reported, path} {
		if err := os.WriteFile(p, []byte("<?php echo 1;"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ev := placementOf(t, reported, 0)
	ev.Path = path
	fm := placementTestMonitor(make(chan alert.Finding, 4))

	start := time.Now()
	fm.handlePlacement(ev)

	if got := queuedPlacements(t, fm); len(got) != 0 {
		t.Fatalf("a different inode at the path queued %d events", len(got))
	}
	if stats := fm.EventStats(); stats.PlacementUnverified != 1 || stats.Received != 0 {
		t.Fatalf("stats = %+v, want one unverified placement", stats)
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Fatalf("gave up after %v, want both retries (50 ms and 200 ms)", elapsed)
	}
}

func TestPlacementUninterestingNameNeverQueued(t *testing.T) {
	// Not under a shared temp tree: admission takes every file written there.
	dir := eventFilterDir(t)
	staged, path := filepath.Join(dir, "a.tmp"), filepath.Join(dir, "b.tmp")
	if err := os.WriteFile(staged, []byte("scratch"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatal(err)
	}
	fm := placementTestMonitor(make(chan alert.Finding, 4))

	fm.handlePlacement(placementOf(t, path, 0))

	if got := queuedPlacements(t, fm); len(got) != 0 {
		t.Fatalf("uninteresting placement queued %d events", len(got))
	}
	stats := fm.EventStats()
	if stats.Received != 1 || stats.Filtered() != 1 || stats.PlacementUnverified != 0 {
		t.Fatalf("stats = %+v, want one verified event filtered by admission", stats)
	}
}

func TestPlacementSkipsQuarantine(t *testing.T) {
	qdir := t.TempDir()
	t.Cleanup(checks.SetQuarantineDirForTest(qdir))
	path := filepath.Join(qdir, "x.php")
	if err := os.WriteFile(path, []byte(`<?php system($_POST['c']);`), 0o644); err != nil {
		t.Fatal(err)
	}
	fm := placementTestMonitor(make(chan alert.Finding, 4))

	fm.handlePlacement(placementOf(t, path, 0))

	if got := queuedPlacements(t, fm); len(got) != 0 {
		t.Fatalf("quarantined copy queued %d events", len(got))
	}
	if stats := fm.EventStats(); stats != (EventStats{}) {
		t.Fatalf("stats = %+v, want the quarantine path skipped before open", stats)
	}
}

func TestPlacementKeepsRestoreWriterChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.php")
	stubRemovedFileAt(t, map[string]checks.RemovedFile{path: removalOf(path, restoredPayload, 9)})
	var gotPID int
	prev := restoreWriterChain
	restoreWriterChain = func(pid int, _ time.Time) []int {
		gotPID = pid
		return []int{writerPID, 900}
	}
	t.Cleanup(func() { restoreWriterChain = prev })
	// The restore loop writes elsewhere and renames over the quarantined path.
	staged := filepath.Join(dir, ".index.php.swp")
	if err := os.WriteFile(staged, []byte(restoredPayload), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)

	fm.handlePlacement(placementOf(t, path, writerPID))

	events := queuedPlacements(t, fm)
	if len(events) != 1 {
		t.Fatalf("queued %d events, want the restored file once", len(events))
	}
	if gotPID != writerPID {
		t.Fatalf("writer chain captured for pid %d, want %d", gotPID, writerPID)
	}
	fm.analyzeFile(events[0])
	close(alerts)
	var found []alert.Finding
	for f := range alerts {
		found = append(found, f)
	}
	got := restoredFindings(found)
	if len(got) != 1 || got[0].PID != writerPID || !reflect.DeepEqual(got[0].WriterChain, []int{writerPID, 900}) {
		t.Fatalf("restore findings = %+v, want one naming pid %d and its chain", got, writerPID)
	}
}
