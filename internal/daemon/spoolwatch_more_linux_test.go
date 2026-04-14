//go:build linux

package daemon

import (
	"bytes"
	"encoding/base64"
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
	emime "github.com/pidginhost/csm/internal/mime"
)

// These tests cover spoolwatch.go branches that aren't already exercised in
// spoolwatch_linux_test.go, spoolwatch_coverage_linux_test.go, or
// spoolwatch_deeper_linux_test.go. All tests use in-process sockets/pipes
// to avoid needing a real fanotify fd.

// --- writeResponse: bytes layout sanity check ----------------------------

func TestSpoolWatcherWriteResponseEncodesStruct(t *testing.T) {
	// Use a pipe; writeResponse should serialize the fanotifyResponse struct
	// into 8 bytes (int32 fd + uint32 response) and write it to sw.fd.
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
	defer func() {
		// closeFd will close fds[1] exactly once.
		sw.closeFd()
	}()

	sw.writeResponse(int32(42), FAN_DENY)

	buf := make([]byte, 32)
	n, err := unix.Read(fds[0], buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != responseSize {
		t.Fatalf("read %d bytes, want %d", n, responseSize)
	}

	// Decode and verify the round-trip values.
	got := *(*fanotifyResponse)(unsafe.Pointer(&buf[0]))
	if got.Fd != 42 {
		t.Errorf("decoded Fd = %d, want 42", got.Fd)
	}
	if got.Response != FAN_DENY {
		t.Errorf("decoded Response = %d, want FAN_DENY (%d)", got.Response, FAN_DENY)
	}
}

// --- writeResponse: failed write closes fd and signals Stop --------------

func TestSpoolWatcherWriteResponseFailureTriggersStop(t *testing.T) {
	// Point sw.fd at an already-closed fd: write returns EBADF and the
	// fatal-failure branch should call closeFd() (no-op now) and Stop().
	// Use a guaranteed-invalid FD (-1) so unix.Write fails with EBADF.
	// Closing a real FD then keeping its number would race with the
	// wake-pipe creation below — Linux reuses the lowest-available FD,
	// so the "closed" number could end up pointing at the wake pipe and
	// the write would succeed.
	var wake [2]int
	if err := unix.Pipe2(wake[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Skipf("pipe2 wake: %v", err)
	}
	defer func() {
		_ = unix.Close(wake[0])
		_ = unix.Close(wake[1])
	}()

	sw := &SpoolWatcher{
		fd:      -1, // invalid - unix.Write returns EBADF
		pipeFds: wake,
		stopCh:  make(chan struct{}),
	}

	// Should not panic. After the failed write, sw.stopCh must be closed
	// because writeResponse's failure path invokes Stop().
	sw.writeResponse(int32(1), FAN_ALLOW)

	select {
	case <-sw.stopCh:
		// OK - Stop was triggered by the failed write
	case <-time.After(time.Second):
		t.Fatal("Stop() should have been triggered by failed write")
	}

	if atomic.LoadInt32(&sw.fdClosed) != 1 {
		t.Error("closeFd() should have been called from writeResponse failure path")
	}
}

// --- drainAndClose: idempotent and closes pipe fds -----------------------

func TestSpoolWatcherDrainAndCloseIdempotent(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Skipf("pipe2: %v", err)
	}

	sw := &SpoolWatcher{
		fd:       -1,
		fdClosed: 1, // skip the real fd close
		pipeFds:  fds,
		scanCh:   make(chan spoolEvent, 1),
		stopCh:   make(chan struct{}),
	}

	// First call should run the body once: closes scanCh and pipe fds.
	sw.drainAndClose()
	// Repeated calls must be no-ops (drainOnce guards them).
	sw.drainAndClose()
	sw.drainAndClose()

	if atomic.LoadInt32(&sw.pipeClosed) != 1 {
		t.Error("pipeClosed should be 1 after drainAndClose")
	}

	// scanCh must be closed.
	_, ok := <-sw.scanCh
	if ok {
		t.Error("scanCh should be closed after drainAndClose")
	}
}

// --- handleSpoolEvent: tempfail mode with parse error → FAN_DENY response

func TestSpoolWatcherHandleSpoolEventTempfailParseErrorDenies(t *testing.T) {
	dir := t.TempDir()

	// Wakeup pipe whose read end becomes the "event fd" (so the deferred
	// unix.Close on evt.fd is harmless).
	var evtPipe [2]int
	if err := unix.Pipe2(evtPipe[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Skipf("pipe2: %v", err)
	}
	defer func() { _ = unix.Close(evtPipe[1]) }()

	// sw.fd must be a writable fd so writeResponse succeeds.
	var respPipe [2]int
	if pipeErr := unix.Pipe2(respPipe[:], unix.O_CLOEXEC); pipeErr != nil {
		t.Skipf("pipe2: %v", pipeErr)
	}
	defer func() {
		_ = unix.Close(respPipe[0])
	}()

	cfg := &config.Config{}
	cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
	cfg.EmailAV.FailMode = "tempfail"

	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{
		cfg:     cfg,
		alertCh: ch,
		fd:      respPipe[1],
		stopCh:  make(chan struct{}),
	}
	defer sw.closeFd()

	evt := spoolEvent{
		path:     filepath.Join(dir, "missing-D"),
		fd:       evtPipe[0],
		needResp: true, // exercise tempfail branch
	}
	sw.handleSpoolEvent(evt)

	// Verify FAN_DENY was written to sw.fd (the response pipe).
	buf := make([]byte, responseSize)
	n, err := unix.Read(respPipe[0], buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if n != responseSize {
		t.Fatalf("read %d bytes, want %d", n, responseSize)
	}
	got := *(*fanotifyResponse)(unsafe.Pointer(&buf[0]))
	if got.Response != FAN_DENY {
		t.Errorf("response = %d, want FAN_DENY (%d)", got.Response, FAN_DENY)
	}

	// Should have emitted email_av_parse_error.
	select {
	case f := <-ch:
		if f.Check != "email_av_parse_error" {
			t.Errorf("Check = %q, want email_av_parse_error", f.Check)
		}
	default:
		t.Fatal("expected email_av_parse_error finding")
	}
}

// --- handleSpoolEvent: clean message with no attachments allows ----------

// buildMinimalEximSpool writes a minimal Exim -H/-D pair with no attachments.
func buildMinimalEximSpool(t *testing.T, dir, msgID string) {
	t.Helper()
	header := "Exim message header file\n" +
		msgID + "\n" +
		"From: sender@example.com\n" +
		"To: recipient@example.com\n" +
		"Subject: hello\n" +
		"MIME-Version: 1.0\n" +
		"Content-Type: text/plain; charset=us-ascii\n" +
		"\n"
	hPath := filepath.Join(dir, msgID+"-H")
	dPath := filepath.Join(dir, msgID+"-D")
	if err := os.WriteFile(hPath, []byte(header), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dPath, []byte("just a plain text body, no attachments\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolWatcherHandleSpoolEventNoAttachmentsAllows(t *testing.T) {
	dir := t.TempDir()
	msgID := "1aBcDe-000001-XX"
	buildMinimalEximSpool(t, dir, msgID)

	// Event fd: real fd that defer-close is allowed to close.
	tmpFd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Skipf("open dir: %v", err)
	}

	cfg := &config.Config{}
	cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
	cfg.EmailAV.FailMode = "open"

	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{
		cfg:      cfg,
		alertCh:  ch,
		fdClosed: 1, // no real fanotify fd
		stopCh:   make(chan struct{}),
	}

	evt := spoolEvent{
		path:     filepath.Join(dir, msgID+"-D"),
		fd:       tmpFd,
		needResp: false, // notification mode - skip writeResponse
	}
	// Must not panic, must not emit any finding (clean, no attachments).
	sw.handleSpoolEvent(evt)

	select {
	case f := <-ch:
		t.Errorf("unexpected finding for clean message: %+v", f)
	default:
		// OK
	}
}

// --- handleSpoolEvent: infected with successful quarantine → FAN_DENY ---

// alwaysInfectedScanner is a minimal Scanner that always reports an infection.
type alwaysInfectedScanner struct{}

func (alwaysInfectedScanner) Name() string    { return "stub-infected" }
func (alwaysInfectedScanner) Available() bool { return true }
func (alwaysInfectedScanner) Scan(_ string) (emailav.Verdict, error) {
	return emailav.Verdict{Infected: true, Signature: "TEST.Sig", Severity: "critical"}, nil
}

// buildEximSpoolWithAttachment writes a multipart/mixed -H/-D pair with one
// base64-encoded attachment so MIME parsing yields >0 parts.
func buildEximSpoolWithAttachment(t *testing.T, dir, msgID string) {
	t.Helper()
	payload := bytes.Repeat([]byte("X"), 64)
	encoded := base64.StdEncoding.EncodeToString(payload)
	boundary := "BOUND"
	body := "--" + boundary + "\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"see attachment\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: application/octet-stream; name=\"file.bin\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"file.bin\"\r\n\r\n" +
		encoded + "\r\n" +
		"--" + boundary + "--\r\n"

	header := "Exim message header file\n" +
		msgID + "\n" +
		"From: sender@example.com\n" +
		"To: recipient@example.com\n" +
		"Subject: with attachment\n" +
		"MIME-Version: 1.0\n" +
		"Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\n" +
		"\n"
	hPath := filepath.Join(dir, msgID+"-H")
	dPath := filepath.Join(dir, msgID+"-D")
	if err := os.WriteFile(hPath, []byte(header), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dPath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolWatcherHandleSpoolEventInfectedQuarantineSucceeds(t *testing.T) {
	dir := t.TempDir()
	msgID := "1aBcDe-INFECT-XX"
	buildEximSpoolWithAttachment(t, dir, msgID)

	// Quarantine base dir
	qDir := t.TempDir()
	quar := emailav.NewQuarantine(qDir)
	orch := emailav.NewOrchestrator([]emailav.Scanner{alwaysInfectedScanner{}}, 5*time.Second)

	// Need a valid event fd that gets closed via defer.
	tmpFd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Skipf("open dir: %v", err)
	}
	// Need writable sw.fd because needResp=true triggers writeResponse.
	var respPipe [2]int
	if pipeErr := unix.Pipe2(respPipe[:], unix.O_CLOEXEC); pipeErr != nil {
		t.Skipf("pipe2: %v", pipeErr)
	}
	defer func() { _ = unix.Close(respPipe[0]) }()

	cfg := &config.Config{}
	cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
	cfg.EmailAV.MaxArchiveDepth = 1
	cfg.EmailAV.MaxArchiveFiles = 10
	cfg.EmailAV.MaxExtractionSize = 10 * 1024 * 1024
	cfg.EmailAV.FailMode = "open"
	cfg.EmailAV.QuarantineInfected = true

	ch := make(chan alert.Finding, 8)
	sw := &SpoolWatcher{
		cfg:          cfg,
		alertCh:      ch,
		orchestrator: orch,
		quarantine:   quar,
		fd:           respPipe[1],
		stopCh:       make(chan struct{}),
	}
	defer sw.closeFd()

	// Override allowedSpoolDirs via reflection-free approach: write the spool
	// files into the quarantine-allowed temp dir and let it move. Actually
	// QuarantineMessage doesn't validate spoolDir against allowedSpoolDirs in
	// the move path - it just calls moveFile(src, dst). So our temp dir works.
	evt := spoolEvent{
		path:     filepath.Join(dir, msgID+"-D"),
		fd:       tmpFd,
		needResp: true,
	}
	sw.handleSpoolEvent(evt)

	// Read response - must be FAN_DENY (quarantine succeeded).
	buf := make([]byte, responseSize)
	n, err := unix.Read(respPipe[0], buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if n != responseSize {
		t.Fatalf("read %d bytes, want %d", n, responseSize)
	}
	got := *(*fanotifyResponse)(unsafe.Pointer(&buf[0]))
	if got.Response != FAN_DENY {
		t.Errorf("response = %d, want FAN_DENY", got.Response)
	}

	// Must have emitted at least one email_malware finding.
	sawMalware := false
drain:
	for {
		select {
		case f := <-ch:
			if f.Check == "email_malware" {
				sawMalware = true
			}
		default:
			break drain
		}
	}
	if !sawMalware {
		t.Error("expected email_malware finding")
	}

	// Verify quarantine dir was created with the message.
	if _, err := os.Stat(filepath.Join(qDir, msgID)); err != nil {
		t.Errorf("quarantine dir not created: %v", err)
	}
}

// --- handleSpoolEvent: infected, quarantine disabled, fail-open ---------

func TestSpoolWatcherHandleSpoolEventInfectedQuarantineDisabledAllows(t *testing.T) {
	dir := t.TempDir()
	msgID := "1aBcDe-NOQUAR-XX"
	buildEximSpoolWithAttachment(t, dir, msgID)

	orch := emailav.NewOrchestrator([]emailav.Scanner{alwaysInfectedScanner{}}, 5*time.Second)

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
	cfg.EmailAV.QuarantineInfected = false // disabled

	ch := make(chan alert.Finding, 8)
	sw := &SpoolWatcher{
		cfg:          cfg,
		alertCh:      ch,
		orchestrator: orch,
		fdClosed:     1, // no fanotify fd
		stopCh:       make(chan struct{}),
	}

	evt := spoolEvent{
		path:     filepath.Join(dir, msgID+"-D"),
		fd:       tmpFd,
		needResp: false, // notification mode
	}
	sw.handleSpoolEvent(evt)

	// Should still emit email_malware even when quarantine is off.
	sawMalware := false
drain:
	for {
		select {
		case f := <-ch:
			if f.Check == "email_malware" {
				sawMalware = true
			}
		default:
			break drain
		}
	}
	if !sawMalware {
		t.Error("expected email_malware finding even with quarantine disabled")
	}
}

// --- handleSpoolEvent: infected with quarantine error in tempfail mode ---

func TestSpoolWatcherHandleSpoolEventInfectedQuarantineErrorTempfail(t *testing.T) {
	dir := t.TempDir()
	msgID := "1aBcDe-QFAIL-XX"
	buildEximSpoolWithAttachment(t, dir, msgID)

	orch := emailav.NewOrchestrator([]emailav.Scanner{alwaysInfectedScanner{}}, 5*time.Second)

	// Quarantine pointed at an unwritable path: MkdirAll under "/dev/null/..."
	// fails on Linux, so QuarantineMessage returns an error.
	quar := emailav.NewQuarantine("/dev/null/csm-quar-impossible")

	tmpFd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Skipf("open dir: %v", err)
	}

	var respPipe [2]int
	if pipeErr := unix.Pipe2(respPipe[:], unix.O_CLOEXEC); pipeErr != nil {
		t.Skipf("pipe2: %v", pipeErr)
	}
	defer func() { _ = unix.Close(respPipe[0]) }()

	cfg := &config.Config{}
	cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
	cfg.EmailAV.MaxArchiveDepth = 1
	cfg.EmailAV.MaxArchiveFiles = 10
	cfg.EmailAV.MaxExtractionSize = 10 * 1024 * 1024
	cfg.EmailAV.FailMode = "tempfail"
	cfg.EmailAV.QuarantineInfected = true

	ch := make(chan alert.Finding, 8)
	sw := &SpoolWatcher{
		cfg:          cfg,
		alertCh:      ch,
		orchestrator: orch,
		quarantine:   quar,
		fd:           respPipe[1],
		stopCh:       make(chan struct{}),
	}
	defer sw.closeFd()

	evt := spoolEvent{
		path:     filepath.Join(dir, msgID+"-D"),
		fd:       tmpFd,
		needResp: true,
	}
	sw.handleSpoolEvent(evt)

	// Quarantine failed + tempfail → FAN_DENY (defer delivery).
	buf := make([]byte, responseSize)
	n, err := unix.Read(respPipe[0], buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if n != responseSize {
		t.Fatalf("read %d bytes, want %d", n, responseSize)
	}
	got := *(*fanotifyResponse)(unsafe.Pointer(&buf[0]))
	if got.Response != FAN_DENY {
		t.Errorf("response = %d, want FAN_DENY (tempfail+quarantine error)", got.Response)
	}

	// Should have emitted email_av_quarantine_error (and email_malware).
	sawQErr := false
drain:
	for {
		select {
		case f := <-ch:
			if f.Check == "email_av_quarantine_error" {
				sawQErr = true
			}
		default:
			break drain
		}
	}
	if !sawQErr {
		t.Error("expected email_av_quarantine_error finding")
	}
}

// --- handleSpoolEvent: AllEnginesDown in tempfail mode → FAN_DENY -------

// noEnginesAvailableScanner reports unavailable so orchestrator marks
// AllEnginesDown=true.
type noEnginesAvailableScanner struct{}

func (noEnginesAvailableScanner) Name() string    { return "stub-down" }
func (noEnginesAvailableScanner) Available() bool { return false }
func (noEnginesAvailableScanner) Scan(_ string) (emailav.Verdict, error) {
	return emailav.Verdict{}, nil
}

func TestSpoolWatcherHandleSpoolEventAllEnginesDownTempfail(t *testing.T) {
	dir := t.TempDir()
	msgID := "1aBcDe-DOWN-XX"
	buildEximSpoolWithAttachment(t, dir, msgID)

	orch := emailav.NewOrchestrator([]emailav.Scanner{noEnginesAvailableScanner{}}, 5*time.Second)

	tmpFd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Skipf("open dir: %v", err)
	}

	var respPipe [2]int
	if pipeErr := unix.Pipe2(respPipe[:], unix.O_CLOEXEC); pipeErr != nil {
		t.Skipf("pipe2: %v", pipeErr)
	}
	defer func() { _ = unix.Close(respPipe[0]) }()

	cfg := &config.Config{}
	cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
	cfg.EmailAV.MaxArchiveDepth = 1
	cfg.EmailAV.MaxArchiveFiles = 10
	cfg.EmailAV.MaxExtractionSize = 10 * 1024 * 1024
	cfg.EmailAV.FailMode = "tempfail"

	ch := make(chan alert.Finding, 8)
	sw := &SpoolWatcher{
		cfg:          cfg,
		alertCh:      ch,
		orchestrator: orch,
		fd:           respPipe[1],
		stopCh:       make(chan struct{}),
	}
	defer sw.closeFd()

	evt := spoolEvent{
		path:     filepath.Join(dir, msgID+"-D"),
		fd:       tmpFd,
		needResp: true,
	}
	sw.handleSpoolEvent(evt)

	buf := make([]byte, responseSize)
	n, err := unix.Read(respPipe[0], buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if n != responseSize {
		t.Fatalf("read %d bytes, want %d", n, responseSize)
	}
	got := *(*fanotifyResponse)(unsafe.Pointer(&buf[0]))
	if got.Response != FAN_DENY {
		t.Errorf("response = %d, want FAN_DENY (AllEnginesDown+tempfail)", got.Response)
	}

	// Verify a degraded warning was emitted.
	sawDegraded := false
drain:
	for {
		select {
		case f := <-ch:
			if f.Check == "email_av_degraded" {
				sawDegraded = true
			}
		default:
			break drain
		}
	}
	if !sawDegraded {
		t.Error("expected email_av_degraded finding")
	}
}

// --- handleSpoolEvent: AllEnginesDown in fail-open allows ---------------

func TestSpoolWatcherHandleSpoolEventAllEnginesDownFailOpenAllows(t *testing.T) {
	dir := t.TempDir()
	msgID := "1aBcDe-DOWNOK-XX"
	buildEximSpoolWithAttachment(t, dir, msgID)

	orch := emailav.NewOrchestrator([]emailav.Scanner{noEnginesAvailableScanner{}}, 5*time.Second)

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

	ch := make(chan alert.Finding, 8)
	sw := &SpoolWatcher{
		cfg:          cfg,
		alertCh:      ch,
		orchestrator: orch,
		fdClosed:     1, // no fanotify fd
		stopCh:       make(chan struct{}),
	}

	evt := spoolEvent{
		path:     filepath.Join(dir, msgID+"-D"),
		fd:       tmpFd,
		needResp: false,
	}
	// Should not panic; emits degraded warning, allows delivery.
	sw.handleSpoolEvent(evt)

	sawDegraded := false
drain:
	for {
		select {
		case f := <-ch:
			if f.Check == "email_av_degraded" {
				sawDegraded = true
			}
		default:
			break drain
		}
	}
	if !sawDegraded {
		t.Error("expected email_av_degraded finding (fail-open path)")
	}
}

// --- ensure we don't shadow the existing helper signature ----------------

// Sanity: emime.Limits zero-value compiles in this file (used in source).
func TestEmimeLimitsZeroValue(t *testing.T) {
	var l emime.Limits
	if l.MaxAttachmentSize != 0 {
		t.Errorf("zero limits.MaxAttachmentSize = %d", l.MaxAttachmentSize)
	}
}
