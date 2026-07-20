//go:build linux

package daemon

import (
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
)

func newDropperWiringTestMonitor(docroot string, ttl time.Duration) *FileMonitor {
	fm := &FileMonitor{
		alertCh: make(chan alert.Finding, 8),
		stopCh:  make(chan struct{}),
	}
	fm.dropper = newDropperEngine(dropperEngineConfig{ttl: ttl, selfPID: 99999})
	fm.dropperQuarantines = newDropperQuarantineLedger(ttl + time.Minute)
	fm.dropperDocroots.Store([]string{docroot})
	return fm
}

func TestDropperObservePreservesFDOffsetAndRefreshesCreate(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, ".temp.123.payload.php")
	content := []byte("<?php if (isset($_GET['x'])) { system($_GET['x']); }")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	fm := newDropperWiringTestMonitor(docroot, time.Minute)
	created := fm.observeDropperCandidate(fileEvent{
		path: path, fd: int(f.Fd()), pid: 4242, mask: FAN_CREATE,
	}, "pid=4242 cmd=php")
	if created == nil || !created.Created {
		t.Fatalf("create observation = %+v, want admitted Created candidate", created)
	}
	closed := fm.observeDropperCandidate(fileEvent{
		path: path, fd: int(f.Fd()), pid: 4242, mask: FAN_CLOSE_WRITE,
	}, "pid=4242 cmd=php")
	if closed == nil {
		t.Fatal("close-write did not refresh the create candidate")
	}
	if got, err := f.Seek(0, io.SeekCurrent); err != nil || got != 7 {
		t.Fatalf("event fd offset = %d, err=%v, want 7", got, err)
	}
	if closed.Digest != sha256.Sum256(content) || !closed.DigestKnown {
		t.Fatalf("close digest known=%v digest=%x, want full SHA-256", closed.DigestKnown, closed.Digest)
	}

	due := fm.dropper.tr.Due(time.Now().Add(2 * time.Minute))
	if len(due) != 1 {
		t.Fatalf("tracked candidates = %d, want one merged create/close entry", len(due))
	}
	if !due[0].Created || due[0].Size != int64(len(content)) || !due[0].DigestKnown {
		t.Fatalf("merged candidate = %+v", due[0])
	}
}

func TestDropperDigestFromFDEmptyAndChunked(t *testing.T) {
	for _, content := range [][]byte{nil, make([]byte, 3*dropperDigestChunk+17)} {
		f, err := os.CreateTemp(t.TempDir(), "digest-")
		if err != nil {
			t.Fatal(err)
		}
		if len(content) > 0 {
			for i := range content {
				content[i] = byte(i % 251)
			}
			if _, err := f.Write(content); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := f.Seek(3, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		got, ok := digestFromFD(int(f.Fd()), int64(len(content)))
		if !ok || got != sha256.Sum256(content) {
			t.Errorf("digest len=%d known=%v got=%x", len(content), ok, got)
		}
		if offset, err := f.Seek(0, io.SeekCurrent); err != nil || offset != 3 {
			t.Errorf("digest changed fd offset to %d, err=%v", offset, err)
		}
		_ = f.Close()
	}
}

func TestDropperObserveSkipsDigestWithoutRenameShape(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, "payload.php")
	if err := os.WriteFile(path, []byte("<?php return true;"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fm := newDropperWiringTestMonitor(docroot, time.Minute)
	c := fm.observeDropperCandidate(fileEvent{
		path: path, fd: int(f.Fd()), pid: 4242, mask: FAN_CREATE | FAN_CLOSE_WRITE,
	}, "")
	if c == nil {
		t.Fatal("PHP candidate was not admitted")
	}
	if c.DigestKnown {
		t.Fatal("non-rename candidate paid for an unused full-file digest")
	}
}

func TestDropperHandleEventPreservesMaskForAtomicStage(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, ".temp.123.payload.php")
	if err := os.WriteFile(path, []byte("<?php return true;"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	dupFD, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}

	fm := newDropperWiringTestMonitor(docroot, time.Minute)
	fm.analyzerCh = make(chan fileEvent, 1)
	fm.handleEvent(dupFD, 4242, FAN_CREATE|FAN_CLOSE_WRITE)
	event := <-fm.analyzerCh
	defer func() { _ = unix.Close(event.fd) }()
	if event.mask&FAN_CREATE == 0 || event.mask&FAN_CLOSE_WRITE == 0 {
		t.Fatalf("queued mask = %#x, want CREATE|CLOSE_WRITE", event.mask)
	}
	if !event.dropperOnly {
		t.Fatal("atomic staging path must bypass normal content checks")
	}
}

func TestDropperHandleEventKeepsAlreadyDeletedPHP(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, "short-lived.php")
	if err := os.WriteFile(path, []byte("<?php return true;"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	dupFD, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	fm := newDropperWiringTestMonitor(docroot, time.Minute)
	fm.analyzerCh = make(chan fileEvent, 1)
	fm.handleEvent(dupFD, 4242, FAN_CREATE|FAN_CLOSE_WRITE)
	event := <-fm.analyzerCh
	defer func() { _ = unix.Close(event.fd) }()
	if event.path != path {
		t.Fatalf("queued deleted path = %q, want %q", event.path, path)
	}
	if candidate := fm.observeDropperCandidate(event, ""); candidate == nil {
		t.Fatal("already-deleted PHP event was not admitted")
	}
}

func TestDropperHandleEventAdmitsArbitraryExecutableUnderDocroot(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, "worker.bin")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nid\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	dupFD, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}

	fm := newDropperWiringTestMonitor(docroot, time.Minute)
	fm.analyzerCh = make(chan fileEvent, 1)
	fm.handleEvent(dupFD, 4242, FAN_CREATE)
	event := <-fm.analyzerCh
	defer func() { _ = unix.Close(event.fd) }()
	if !event.dropperOnly {
		t.Fatal("arbitrary executable should be queued only for dropper tracking")
	}
}

func TestDropperHandleEventAdmitsInheritedPHPHandler(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, "payload.jpg")
	if err := os.WriteFile(filepath.Join(docroot, ".htaccess"),
		[]byte("AddHandler application/x-httpd-php .jpg\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("<?php system($_GET['x']);"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	dupFD, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}

	fm := newDropperWiringTestMonitor(docroot, time.Minute)
	fm.analyzerCh = make(chan fileEvent, 1)
	fm.handleEvent(dupFD, 4242, FAN_CREATE|FAN_CLOSE_WRITE)
	event := <-fm.analyzerCh
	defer func() { _ = unix.Close(event.fd) }()
	if !event.dropperOnly || !event.phpExecutable {
		t.Fatalf("handler-mapped event = %+v, want dropper-only PHP executable", event)
	}
	c := fm.observeDropperCandidate(event, "")
	if c == nil || !c.PHPExecutable {
		t.Fatalf("handler-mapped candidate = %+v", c)
	}
}

func TestDropperPHPHandlerCacheInvalidatesOnHtaccessEvent(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, "payload.jpg")
	if err := os.WriteFile(path, []byte("<?php return true;"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fm := newDropperWiringTestMonitor(docroot, time.Minute)
	if interesting, _ := fm.isDropperInteresting(path, int(f.Fd())); interesting {
		t.Fatal("plain .jpg unexpectedly executable before handler mapping")
	}
	if err := os.WriteFile(filepath.Join(docroot, ".htaccess"),
		[]byte("AddHandler application/x-httpd-php .jpg\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fm.invalidateDropperPHPHandlerCache(filepath.Join(docroot, ".htaccess"))
	if interesting, phpExecutable := fm.isDropperInteresting(path, int(f.Fd())); !interesting || !phpExecutable {
		t.Fatalf("handler-mapped .jpg interesting=%v phpExecutable=%v", interesting, phpExecutable)
	}
	if err := os.Remove(filepath.Join(docroot, ".htaccess")); err != nil {
		t.Fatal(err)
	}
	fm.dropperHandlerMu.Lock()
	for key, entry := range fm.dropperHandlerCache {
		entry.loaded = time.Now().Add(-dropperPHPHandlerCacheTTL)
		fm.dropperHandlerCache[key] = entry
	}
	fm.dropperHandlerMu.Unlock()
	if interesting, _ := fm.isDropperInteresting(path, int(f.Fd())); interesting {
		t.Fatal("expired handler cache survived .htaccess removal")
	}
}

func TestDropperOnlyAtomicStageRetainsSuspiciousContentVerdict(t *testing.T) {
	docroot := t.TempDir()
	path := filepath.Join(docroot, ".temp.123.payload.php")
	content := []byte("<?php system($_GET['x']);")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	fm := newDropperWiringTestMonitor(docroot, time.Minute)
	fm.analyzeFile(fileEvent{
		path: path, fd: int(f.Fd()), mask: FAN_CREATE | FAN_CLOSE_WRITE,
		dropperOnly: true,
	})
	due := fm.dropper.tr.Due(time.Now().Add(2 * time.Minute))
	if len(due) != 1 || !due[0].ContentSuspicious {
		t.Fatalf("tracked candidates = %+v, want suspicious atomic-stage content", due)
	}
	if got := len(fm.alertCh); got != 0 {
		t.Fatalf("dropper-only staging path entered normal alert pipeline: %d alert(s)", got)
	}
}

func TestDropperProbeDistinguishesENOENTFromENOTDIR(t *testing.T) {
	docroot := t.TempDir()
	prober := dropperFSProbe{}
	absent := prober.probe(dropperCandidate{
		Path: filepath.Join(docroot, "gone.php"), Docroot: docroot,
	})
	if !absent.Conclusive || absent.AtPath != nil {
		t.Fatalf("ENOENT probe = %+v, want conclusive absence", absent)
	}

	parentFile := filepath.Join(docroot, "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	transient := prober.probe(dropperCandidate{
		Path: filepath.Join(parentFile, "child.php"), Docroot: docroot,
	})
	if transient.Conclusive {
		t.Fatalf("ENOTDIR probe = %+v, want inconclusive", transient)
	}
}

func TestDropperProbeUsesSingleFDSnapshotForSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	state, err := statPathToFileState(link, true)
	if err != nil {
		t.Fatal(err)
	}
	if state.mode&unix.S_IFMT != unix.S_IFLNK {
		t.Fatalf("mode = %#o, want symlink", state.mode)
	}
	if state.file.DigestKnown {
		t.Fatal("O_PATH symlink snapshot must not claim a content digest")
	}
}

func TestDropperFindRenameTargetSelectsMatchingDestination(t *testing.T) {
	docroot := t.TempDir()
	source := filepath.Join(docroot, "wp-content", "upgrade", "stage", "sample", "x.php")
	pluginTarget := filepath.Join(docroot, "wp-content", "plugins", "sample", "x.php")
	themeTarget := filepath.Join(docroot, "wp-content", "themes", "sample", "x.php")
	for _, target := range []string{pluginTarget, themeTarget} {
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(pluginTarget, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantContent := []byte("<?php return 'matching theme';")
	if err := os.WriteFile(themeTarget, wantContent, 0o644); err != nil {
		t.Fatal(err)
	}
	c := dropperCandidate{
		Path: source, Docroot: docroot, Size: int64(len(wantContent)),
		Digest: sha256.Sum256(wantContent), DigestKnown: true,
	}
	target, _, ok, err := dropperFindRenameTarget(c)
	if err != nil || !ok || target != themeTarget {
		t.Fatalf("rename target = %q ok=%v err=%v, want %q", target, ok, err, themeTarget)
	}
}

func TestDropperProbeMatchesExactQuarantineRecord(t *testing.T) {
	docroot := t.TempDir()
	content := []byte("<?php system($_GET['x']);")
	original := filepath.Join(docroot, "gone.php")
	quarantine := filepath.Join(t.TempDir(), "quarantined")
	if err := os.WriteFile(quarantine, content, 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := statPathToFileState(quarantine, false)
	if err != nil {
		t.Fatal(err)
	}
	ledger := newDropperQuarantineLedger(time.Minute)
	ledger.record(original, state.file, time.Now())
	c := dropperCandidate{
		Path: original, Docroot: docroot, Device: state.file.Device,
		Inode: state.file.Inode, Birth: state.file.Birth, BirthKnown: state.file.BirthKnown,
		Size: int64(len(content)), Digest: sha256.Sum256(content), DigestKnown: true,
	}
	replay := c
	replay.Inode++
	if ledger.matched(replay, time.Now()) {
		t.Fatal("identical content from a different inode consumed quarantine record")
	}
	probe := (dropperFSProbe{quarantines: ledger}).probe(c)
	if !probe.Conclusive || !probe.QuarantineMatched {
		t.Fatalf("quarantine probe = %+v, want exact match", probe)
	}
	if ledger.matched(c, time.Now()) {
		t.Fatal("quarantine record must be consumed after a match")
	}
}

func TestDropperOverflowReportsOnlyNewLoss(t *testing.T) {
	fm := newDropperWiringTestMonitor(t.TempDir(), time.Minute)
	fm.dropper.tr.maxTracked = 0
	c := dropperCandidate{Path: "/x.php", Device: 1, Inode: 1}
	if fm.dropper.tr.Observe(c) {
		t.Fatal("zero-capacity tracker accepted candidate")
	}
	fm.reportDropperOverflow()
	fm.reportDropperOverflow()
	if got := len(fm.alertCh); got != 1 {
		t.Fatalf("alerts after one loss and two reports = %d, want 1", got)
	}
	c.Inode++
	fm.dropper.tr.Observe(c)
	fm.reportDropperOverflow()
	if got := len(fm.alertCh); got != 1 {
		t.Fatalf("rate-limited alerts = %d, want 1", got)
	}
	fm.lastDropperOverflowReport = time.Now().Add(-time.Minute)
	fm.reportDropperOverflow()
	if got := len(fm.alertCh); got != 2 {
		t.Fatalf("alerts after a new loss = %d, want 2", got)
	}
}

func TestDropperProbeLoopStopsAndBalancesWaitGroup(t *testing.T) {
	fm := newDropperWiringTestMonitor(t.TempDir(), time.Minute)
	fm.wg.Add(1)
	go fm.dropperProbeLoop()
	close(fm.stopCh)
	done := make(chan struct{})
	go func() {
		fm.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dropper probe loop did not stop")
	}
}
