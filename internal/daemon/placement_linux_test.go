//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// A file renamed or linked into a site raises no close-write, so the
// placement backends report it and handlePlacement must give it the same
// analysis and response a write in place gets.

func placementTestMonitor(alerts chan alert.Finding) *FileMonitor {
	fm := shutdownDrainTestMonitor(8)
	fm.alertCh = alerts
	return fm
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
