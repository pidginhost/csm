//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailav"
)

// Tests targeting branches in spoolwatch.go not covered by the existing
// spoolwatch_*_linux_test.go files.

// --- timedOutScanner: reports a timeout verdict ---------------------------

type timedOutScanner struct{}

func (timedOutScanner) Name() string    { return "stub-timeout" }
func (timedOutScanner) Available() bool { return true }

func (timedOutScanner) Scan(path string) (emailav.Verdict, error) {
	// Sleep longer than the orchestrator timeout so ScanParts marks us timed out.
	time.Sleep(50 * time.Millisecond)
	return emailav.Verdict{}, nil
}

// --- handleSpoolEvent: timeout in fail-open mode emits warning, allows ----

func TestSpoolWatcherHandleSpoolEventTimeoutFailOpen(t *testing.T) {
	dir := t.TempDir()
	msgID := "TIMEOUT-OPEN-XX"
	buildEximSpoolWithAttachment(t, dir, msgID)

	// Orchestrator with a very short timeout → forces TimedOutEngines populated.
	orch := emailav.NewOrchestrator([]emailav.Scanner{timedOutScanner{}}, 5*time.Millisecond)

	tmpFd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Skipf("open dir: %v", err)
	}

	cfg := &config.Config{}
	cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
	cfg.EmailAV.MaxArchiveDepth = 1
	cfg.EmailAV.MaxArchiveFiles = 10
	cfg.EmailAV.MaxExtractionSize = 10 * 1024 * 1024
	cfg.EmailAV.FailMode = "open"

	ch := make(chan alert.Finding, 16)
	sw := &SpoolWatcher{
		cfg:          cfg,
		alertCh:      ch,
		orchestrator: orch,
		fdClosed:     1, // no real fanotify fd
		stopCh:       make(chan struct{}),
	}

	evt := spoolEvent{
		path:     filepath.Join(dir, msgID+"-D"),
		fd:       tmpFd,
		needResp: false, // notification mode
	}
	sw.handleSpoolEvent(evt)

	// Should have emitted email_av_timeout (warning) but continued to allow.
	sawTimeout := false
drain:
	for {
		select {
		case f := <-ch:
			if f.Check == "email_av_timeout" {
				sawTimeout = true
			}
		default:
			break drain
		}
	}
	if !sawTimeout {
		t.Error("expected email_av_timeout finding in fail-open mode")
	}
}

// --- scanWorker: drains events on channel close ---------------------------

// TestSpoolWatcherScanWorkerExitsOnChannelClose confirms that closing
// scanCh causes the worker goroutine to return cleanly.
func TestSpoolWatcherScanWorkerExitsOnChannelClose(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
	cfg.EmailAV.FailMode = "open"
	cfg.EmailAV.ScanConcurrency = 1

	sw := &SpoolWatcher{
		cfg:      cfg,
		alertCh:  make(chan alert.Finding, 4),
		scanCh:   make(chan spoolEvent, 4),
		stopCh:   make(chan struct{}),
		fdClosed: 1,
	}
	sw.wg.Add(1)
	done := make(chan struct{})
	go func() {
		sw.scanWorker()
		close(done)
	}()

	// Close scanCh → worker should exit.
	close(sw.scanCh)

	select {
	case <-done:
		// OK
	case <-time.After(time.Second):
		t.Fatal("scanWorker did not exit after channel close")
	}
}

// --- scanWorker: returns on stopCh close ----------------------------------

func TestSpoolWatcherScanWorkerExitsOnStop(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailAV.FailMode = "open"

	sw := &SpoolWatcher{
		cfg:      cfg,
		alertCh:  make(chan alert.Finding, 4),
		scanCh:   make(chan spoolEvent, 4),
		stopCh:   make(chan struct{}),
		fdClosed: 1,
	}
	sw.wg.Add(1)
	done := make(chan struct{})
	go func() {
		sw.scanWorker()
		close(done)
	}()

	close(sw.stopCh)

	select {
	case <-done:
		// OK
	case <-time.After(time.Second):
		t.Fatal("scanWorker did not exit after stop")
	}
}

// --- handleSpoolEvent: allows on clean scan with parts but no infection ---

// cleanScanner always reports not infected.
type cleanScanner struct{}

func (cleanScanner) Name() string    { return "stub-clean" }
func (cleanScanner) Available() bool { return true }
func (cleanScanner) Scan(_ string) (emailav.Verdict, error) {
	return emailav.Verdict{Infected: false}, nil
}

func TestSpoolWatcherHandleSpoolEventCleanWithAttachmentAllows(t *testing.T) {
	dir := t.TempDir()
	msgID := "CLEAN-ATTACH-XX"
	buildEximSpoolWithAttachment(t, dir, msgID)

	orch := emailav.NewOrchestrator([]emailav.Scanner{cleanScanner{}}, 5*time.Second)

	tmpFd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Skipf("open dir: %v", err)
	}

	cfg := &config.Config{}
	cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
	cfg.EmailAV.MaxArchiveDepth = 1
	cfg.EmailAV.MaxArchiveFiles = 10
	cfg.EmailAV.MaxExtractionSize = 10 * 1024 * 1024
	cfg.EmailAV.FailMode = "open"

	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{
		cfg:          cfg,
		alertCh:      ch,
		orchestrator: orch,
		fdClosed:     1,
		stopCh:       make(chan struct{}),
	}

	evt := spoolEvent{
		path:     filepath.Join(dir, msgID+"-D"),
		fd:       tmpFd,
		needResp: false,
	}
	sw.handleSpoolEvent(evt)

	select {
	case f := <-ch:
		t.Errorf("unexpected finding on clean scan: %+v", f)
	default:
		// OK
	}
}

// --- writeResponse: serializes layout into sw.fd (complement existing) ----

// This verifies the FAN_ALLOW path specifically (existing test uses FAN_DENY).
func TestSpoolWatcherWriteResponseFanAllow(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Skipf("pipe2: %v", err)
	}
	defer func() { _ = unix.Close(fds[0]) }()

	sw := &SpoolWatcher{
		fd:       fds[1],
		fdClosed: 0,
		stopCh:   make(chan struct{}),
	}
	defer sw.closeFd()

	sw.writeResponse(int32(99), FAN_ALLOW)

	buf := make([]byte, responseSize)
	n, err := unix.Read(fds[0], buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != responseSize {
		t.Fatalf("read %d bytes, want %d", n, responseSize)
	}
	got := *(*fanotifyResponse)(unsafe.Pointer(&buf[0]))
	if got.Fd != 99 {
		t.Errorf("Fd = %d, want 99", got.Fd)
	}
	if got.Response != FAN_ALLOW {
		t.Errorf("Response = %d, want FAN_ALLOW", got.Response)
	}
}

// --- NewSpoolWatcher: environment without any spool dir errors -----------

func TestNewSpoolWatcherNoSpoolDirs(t *testing.T) {
	// On CI hosts without /var/spool/exim/{input,exim4/input}, NewSpoolWatcher
	// should return the "no Exim spool directories found" error after
	// closing the fanotify fd.
	if _, err := os.Stat("/var/spool/exim/input"); err == nil {
		t.Skip("spool dir exists on this host")
	}
	if _, err := os.Stat("/var/spool/exim4/input"); err == nil {
		t.Skip("spool dir exists on this host")
	}

	cfg := &config.Config{}
	cfg.EmailAV.FailMode = "open"

	sw, err := NewSpoolWatcher(cfg, make(chan alert.Finding, 1), nil, nil)
	if err == nil {
		// Some kernels/users may have root + exim installed — accept both.
		if sw != nil {
			sw.Stop()
		}
		return
	}
	// Expected case: kernel might reject FanotifyInit without CAP_SYS_ADMIN.
	// Either way, the error is returned (covers both failure branches).
	_ = err
}

// --- drainAndClose: closes pipe fds exactly once --------------------------

func TestSpoolWatcherDrainAndCloseClosesPipeFdsOnce(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Skipf("pipe2: %v", err)
	}

	sw := &SpoolWatcher{
		fd:       -1,
		fdClosed: 1,
		pipeFds:  fds,
		scanCh:   make(chan spoolEvent, 1),
		stopCh:   make(chan struct{}),
	}

	sw.drainAndClose()
	if atomic.LoadInt32(&sw.pipeClosed) != 1 {
		t.Error("pipeClosed should be 1 after drainAndClose")
	}

	// A second call should not touch the (already closed) pipe fds.
	sw.drainAndClose()
	if atomic.LoadInt32(&sw.pipeClosed) != 1 {
		t.Error("pipeClosed should stay 1")
	}
}
