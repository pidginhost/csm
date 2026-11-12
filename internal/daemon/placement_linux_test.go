//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
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
	defer listener.Close()
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
	defer unix.Close(watch)
	if _, err := unix.InotifyAddWatch(watch, path, unix.IN_OPEN); err != nil {
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
	if after := fm.EventStats(); after.Received != before.Received {
		t.Fatalf("stats %+v -> %+v, want the placement skipped before admission", before, after)
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
