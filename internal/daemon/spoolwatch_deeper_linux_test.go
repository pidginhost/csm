//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// These tests target helpers on SpoolWatcher that aren't covered by the
// existing spoolwatch_*_linux_test.go files. All tests work entirely on
// in-memory state: no real fanotify fd is opened.

// --- responseSize matches the fanotifyResponse struct layout -------------

func TestSpoolWatcherResponseSizeConstant(t *testing.T) {
	// responseSize is used by writeResponse to slice the response bytes.
	// Must be 8 (int32 + uint32).
	if responseSize != 8 {
		t.Errorf("responseSize = %d, want 8", responseSize)
	}
}

// --- constants are non-zero and distinct ---------------------------------

func TestSpoolWatcherFanotifyConstants(t *testing.T) {
	if FAN_CLASS_CONTENT == 0 {
		t.Error("FAN_CLASS_CONTENT should be non-zero")
	}
	if FAN_OPEN_PERM == 0 {
		t.Error("FAN_OPEN_PERM should be non-zero")
	}
	if FAN_ALLOW == FAN_DENY {
		t.Error("FAN_ALLOW and FAN_DENY must differ")
	}
	if FAN_ALLOW != 0x01 {
		t.Errorf("FAN_ALLOW = %#x, want 0x01", FAN_ALLOW)
	}
	if FAN_DENY != 0x02 {
		t.Errorf("FAN_DENY = %#x, want 0x02", FAN_DENY)
	}
	if FAN_EVENT_ON_CHILD == 0 {
		t.Error("FAN_EVENT_ON_CHILD should be non-zero")
	}
}

// --- emitFinding severity / check / message propagation ------------------

func TestSpoolWatcherEmitFindingPreservesFields(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}
	sw.emitFinding("email_av_quarantine_error", alert.Critical, "quarantine failed: disk full")

	select {
	case f := <-ch:
		if f.Severity != alert.Critical {
			t.Errorf("Severity = %v, want Critical", f.Severity)
		}
		if f.Check != "email_av_quarantine_error" {
			t.Errorf("Check = %q", f.Check)
		}
		if f.Message != "quarantine failed: disk full" {
			t.Errorf("Message = %q", f.Message)
		}
	default:
		t.Fatal("finding was not delivered")
	}
}

// --- emitDegradedWarning rate limit window -------------------------------

func TestSpoolWatcherEmitDegradedWarningMultipleRapidCalls(t *testing.T) {
	ch := make(chan alert.Finding, 16)
	sw := &SpoolWatcher{alertCh: ch}

	// Three rapid calls — only the first should emit.
	sw.emitDegradedWarning("one")
	sw.emitDegradedWarning("two")
	sw.emitDegradedWarning("three")

	count := 0
drain:
	for {
		select {
		case <-ch:
			count++
		default:
			break drain
		}
	}
	if count != 1 {
		t.Errorf("emissions = %d, want 1 (rate-limited)", count)
	}
}

func TestSpoolWatcherEmitDegradedWarningNilChannelSafe(t *testing.T) {
	// With a nil alertCh, emitFinding's select-default should drop silently.
	// emitDegradedWarning should not panic in that scenario.
	sw := &SpoolWatcher{alertCh: nil}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("emitDegradedWarning panicked with nil channel: %v", r)
		}
	}()
	// Pretend enough time has passed to bypass the rate-limit.
	sw.lastDegradedAt = time.Now().Add(-2 * time.Minute)
	sw.emitDegradedWarning("test")
}

// --- PermissionMode default is false on zero-value struct ----------------

func TestSpoolWatcherPermissionModeZeroValue(t *testing.T) {
	sw := &SpoolWatcher{}
	if sw.PermissionMode() {
		t.Error("zero-value SpoolWatcher should report PermissionMode=false")
	}
}

// --- closeFd only closes once even with a valid fd -----------------------

func TestSpoolWatcherCloseFdClosesRealFd(t *testing.T) {
	// Use a real pipe fd so we can verify close side-effects.
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Skipf("pipe2: %v", err)
	}
	defer func() { _ = unix.Close(fds[1]) }()

	sw := &SpoolWatcher{fd: fds[0]}
	sw.closeFd()
	if atomic.LoadInt32(&sw.fdClosed) != 1 {
		t.Error("fdClosed should be 1 after closeFd")
	}
	// Second call must be a no-op and not try to close again.
	sw.closeFd()
	// Verify we can't read from the closed fd (should return EBADF).
	buf := make([]byte, 1)
	_, err := unix.Read(fds[0], buf)
	if err == nil {
		t.Error("reading from closed fd should error")
	}
}

// --- Stop triggers writeResponse via wakeup pipe -------------------------

func TestSpoolWatcherStopWritesToWakeupPipe(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Skipf("pipe2: %v", err)
	}

	sw := &SpoolWatcher{
		fd:       -1,
		fdClosed: 1, // skip actual fd close
		pipeFds:  fds,
		stopCh:   make(chan struct{}),
	}

	sw.Stop()

	// Reading the other end should yield the wakeup byte.
	buf := make([]byte, 4)
	n, err := unix.Read(fds[0], buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n == 0 {
		t.Fatal("expected wakeup byte to be written to pipe")
	}

	// cleanup: close both ends
	_ = unix.Close(fds[0])
	_ = unix.Close(fds[1])
	atomic.StoreInt32(&sw.pipeClosed, 1)
}

// --- Stop does not write to pipe once pipeClosed is set ------------------

func TestSpoolWatcherStopSkipsPipeWriteAfterClose(t *testing.T) {
	// Use a pipe fd that we will close ourselves first, then set
	// pipeClosed=1 so Stop's write-guarded branch is exercised.
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Skipf("pipe2: %v", err)
	}
	_ = unix.Close(fds[0])
	_ = unix.Close(fds[1])

	sw := &SpoolWatcher{
		fd:         -1,
		fdClosed:   1,
		pipeFds:    fds,
		pipeClosed: 1, // signals Stop to skip the write
		stopCh:     make(chan struct{}),
	}

	// Must not panic or block even though pipe fds are already closed.
	sw.Stop()

	select {
	case <-sw.stopCh:
		// OK
	default:
		t.Fatal("stopCh should be closed")
	}
}

// --- handleSpoolEvent fail-open on a genuine MIME parse error -------------

func TestSpoolWatcherHandleSpoolEventMIMEParseErrorFailOpen(t *testing.T) {
	// A genuine (non-ENOENT) header read failure must still surface an
	// email_av_parse_error finding. We make the -H path a directory so
	// os.ReadFile returns EISDIR, which is distinct from the reception-time
	// race (ENOENT) that MAIL-03 allows silently. tempfail is false and
	// needResp is false, so no response is written.
	dir := t.TempDir()
	msgID := "1parse-000000-EE"
	bodyPath := filepath.Join(dir, msgID+"-D")
	if err := os.WriteFile(bodyPath, []byte(msgID+"-D\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, msgID+"-H"), 0o755); err != nil {
		t.Fatal(err)
	}

	ch := make(chan alert.Finding, 4)
	cfg := &config.Config{}
	cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
	cfg.EmailAV.MaxArchiveDepth = 1
	cfg.EmailAV.MaxArchiveFiles = 10
	cfg.EmailAV.MaxExtractionSize = 10 * 1024 * 1024
	cfg.EmailAV.FailMode = "open"

	// Open a real tempfile to use as the event fd (defer will close it).
	tmpFd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Skipf("open dir: %v", err)
	}

	sw := &SpoolWatcher{
		cfg:      cfg,
		alertCh:  ch,
		stopCh:   make(chan struct{}),
		fdClosed: 1, // skip real close in writeResponse path
	}

	evt := spoolEvent{
		path:     bodyPath,
		fd:       tmpFd,
		pid:      0,
		needResp: false, // notification mode, no permission response needed
	}
	// Must not panic. Emits email_av_parse_error finding.
	sw.handleSpoolEvent(evt)

	select {
	case f := <-ch:
		if f.Check != "email_av_parse_error" {
			t.Errorf("Check = %q, want email_av_parse_error", f.Check)
		}
	default:
		t.Fatal("expected email_av_parse_error finding")
	}
}

// --- spoolEvent struct zero-value ----------------------------------------

func TestSpoolEventZeroValue(t *testing.T) {
	var e spoolEvent
	if e.path != "" || e.fd != 0 || e.pid != 0 || e.needResp {
		t.Errorf("zero-value spoolEvent has non-zero fields: %+v", e)
	}
}

// --- fanotifyResponse struct field assignment ----------------------------

func TestFanotifyResponseStruct(t *testing.T) {
	r := fanotifyResponse{Fd: 7, Response: FAN_ALLOW}
	if r.Fd != 7 {
		t.Errorf("Fd = %d, want 7", r.Fd)
	}
	if r.Response != FAN_ALLOW {
		t.Errorf("Response = %d, want FAN_ALLOW (%d)", r.Response, FAN_ALLOW)
	}
}
