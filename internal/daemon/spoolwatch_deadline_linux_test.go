//go:build linux

package daemon

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/emailav"
)

func TestSpoolDeadlineNotificationSaturationNeverWritesVerdict(t *testing.T) {
	responses := captureResponses(t)
	shortHoldBudget(t, 20*time.Millisecond)
	sw, _ := testHoldWatcher(t)
	sw.permissionMode = false
	sw.scanCh <- spoolEvent{fd: -1}
	fd := openSpoolFD(t)
	sw.dispatchEvent(fd, int32(os.Getpid()+1))
	assertFDClosed(t, int(fd), "notification rejected by full queue")
	if got := responses(); len(got) != 0 {
		t.Fatalf("notification generated permission responses: %+v", got)
	}
}

func TestSpoolDeadlineFullQueueDoesNotBlockReader(t *testing.T) {
	responses := captureResponses(t)
	shortHoldBudget(t, time.Second)
	sw, _ := testHoldWatcher(t)
	sw.scanCh <- spoolEvent{fd: -1}
	fds := []int32{openSpoolFD(t), openSpoolFD(t), openSpoolFD(t)}
	start := time.Now()
	for _, fd := range fds {
		sw.dispatchEvent(fd, int32(os.Getpid()+1))
	}
	if elapsed := time.Since(start); elapsed >= spoolHoldBudget {
		t.Errorf("reader spent %s rejecting a batch; later opens exceeded the hold budget", elapsed)
	}
	if got := responses(); len(got) != len(fds) {
		t.Fatalf("responses = %+v, want all %d opens answered", got, len(fds))
	}
	for _, fd := range fds {
		assertFDClosed(t, int(fd), "rejected batch event")
	}
}

func TestSpoolDeadlineBypassHonorsTempfailAndRecordsLostScans(t *testing.T) {
	responses := captureResponses(t)
	sw, findings := testHoldWatcher(t)
	sw.cfg.EmailAV.FailMode = "tempfail"
	for range spoolHoldExpiryThreshold {
		sw.noteHoldExpiry(time.Now())
	}
	fd := openSpoolFD(t)
	sw.dispatchEvent(fd, int32(os.Getpid()+1))
	got := responses()
	if len(got) != 1 || got[0].response != FAN_DENY {
		t.Errorf("tempfail bypass responses = %+v, want one DENY", got)
	}
	if status := sw.scannerHealth.Snapshot(time.Now()); status.DroppedTotal != 1 || status.RecentDrops != 1 {
		t.Errorf("bypassed scan invisible to health: %+v", status)
	}
	for range 2 {
		sw.dispatchEvent(openSpoolFD(t), int32(os.Getpid()+1))
	}
	if status := sw.scannerHealth.Snapshot(time.Now()); status.DroppedTotal != 3 || status.Status != "degraded" {
		t.Errorf("repeated bypass did not degrade health: %+v", status)
	}
	f := <-findings
	if !strings.Contains(f.Message, "deferred") || strings.Contains(f.Message, "still quarantined") {
		t.Errorf("bypass finding misstates protection: %s", f.Message)
	}
	assertFDClosed(t, int(fd), "bypassed event")
}

func TestSpoolDeadlineFinishDoesNotCloseReusedFD(t *testing.T) {
	responses := captureResponses(t)
	sw, _ := testHoldWatcher(t)
	fd := openSpoolFD(t)
	evt := spoolEvent{fd: int(fd), needResp: true, guard: sw.newHoldGuard(fd, true)}
	evt.finish(sw, FAN_DENY)
	replacement, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if replacement != int(fd) {
		if err := unix.Dup3(replacement, int(fd), unix.O_CLOEXEC); err != nil {
			_ = unix.Close(replacement)
			t.Fatal(err)
		}
		_ = unix.Close(replacement)
	}
	t.Cleanup(func() { _ = unix.Close(int(fd)) })
	evt.finish(sw, FAN_ALLOW)
	evt.guard.expire()
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		t.Errorf("second finish closed an unrelated reused fd: %v", err)
	}
	if got := responses(); len(got) != 1 || got[0].response != FAN_DENY {
		t.Errorf("verdict changed after fd reuse: %+v", got)
	}
}

func TestSpoolDeadlinePanicBeforeHandlerAnswersAndCloses(t *testing.T) {
	responses := captureResponses(t)
	sw, _ := testHoldWatcher(t)
	old := spoolEventHandler
	t.Cleanup(func() { spoolEventHandler = old })
	spoolEventHandler = func(*SpoolWatcher, spoolEvent) { panic("before handler defer") }
	fd := openSpoolFD(t)
	evt := spoolEvent{fd: int(fd), needResp: true, guard: sw.newHoldGuard(fd, true)}
	defer evt.finish(sw, FAN_ALLOW)
	sw.handleSpoolEventSafe(evt)
	if got := responses(); len(got) != 1 || got[0].response != FAN_ALLOW {
		t.Errorf("panic left event unanswered: %+v", got)
	}
	assertFDClosed(t, int(fd), "panicked guarded event")
}

func TestSpoolDeadlineLateQuarantine(t *testing.T) {
	for _, mode := range []string{"open", "tempfail"} {
		t.Run(mode, func(t *testing.T) {
			responses := captureResponses(t)
			sw, evt, qdir, findings := deadlineInfectedEvent(t)
			sw.cfg.EmailAV.FailMode = mode
			evt.guard.expire()
			sw.handleSpoolEventSafe(evt)
			want := uint32(FAN_ALLOW)
			if mode == "tempfail" {
				want = FAN_DENY
			}
			if got := responses(); len(got) != 1 || got[0].response != want {
				t.Errorf("late scan wrote another verdict: %+v", got)
			}
			for _, suffix := range []string{"-H", "-D"} {
				if _, err := os.Stat(filepath.Join(qdir, "deadline-message", "deadline-message"+suffix)); err != nil {
					t.Errorf("quarantine missing %s: %v", suffix, err)
				}
			}
			late := 0
			for len(findings) > 0 {
				if f := <-findings; f.Check == "email_av_late_verdict" {
					late++
				}
			}
			wantLate := 0
			if mode == "open" {
				wantLate = 1
			}
			if late != wantLate {
				t.Errorf("late release warnings = %d, want %d", late, wantLate)
			}
		})
	}
}

func deadlineInfectedEvent(t *testing.T) (*SpoolWatcher, spoolEvent, string, chan alert.Finding) {
	t.Helper()
	dir := t.TempDir()
	buildEximSpoolWithAttachment(t, dir, "deadline-message")
	sw, findings := testHoldWatcher(t)
	sw.cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
	sw.cfg.EmailAV.MaxArchiveDepth = 1
	sw.cfg.EmailAV.MaxArchiveFiles = 10
	sw.cfg.EmailAV.MaxExtractionSize = 10 * 1024 * 1024
	sw.cfg.EmailAV.QuarantineInfected = true
	sw.orchestrator = emailav.NewOrchestrator([]emailav.Scanner{alwaysInfectedScanner{}}, time.Second)
	qdir := t.TempDir()
	sw.quarantine = emailav.NewQuarantine(qdir)
	path := filepath.Join(dir, "deadline-message-D")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	evt := spoolEvent{path: path, fd: fd, needResp: true, guard: sw.newHoldGuard(int32(fd), true)}
	t.Cleanup(func() { evt.finish(sw, FAN_ALLOW) })
	return sw, evt, qdir, findings
}

func TestSpoolDeadlineLateQuarantineLeavesBusySpoolIntact(t *testing.T) {
	captureResponses(t)
	sw, evt, qdir, _ := deadlineInfectedEvent(t)
	fd, err := unix.Open(evt.path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(io.SeekStart)}
	if err := unix.FcntlFlock(uintptr(fd), unix.F_OFD_SETLK, &lock); err != nil {
		t.Fatal(err)
	}
	evt.guard.expire()
	sw.handleSpoolEventSafe(evt)
	assertDeadlineSpoolIntact(t, evt.path, qdir)
}

func TestSpoolDeadlineLateQuarantineRejectsReplacement(t *testing.T) {
	captureResponses(t)
	sw, evt, qdir, _ := deadlineInfectedEvent(t)
	if err := os.Rename(evt.path, evt.path+".old"); err != nil {
		t.Fatal(err)
	}
	buildEximSpoolWithAttachment(t, filepath.Dir(evt.path), "deadline-message")
	evt.guard.expire()
	sw.handleSpoolEventSafe(evt)
	assertDeadlineSpoolIntact(t, evt.path, qdir)
}

func TestSpoolDeadlineLateQuarantinePreservesDeliveryJournal(t *testing.T) {
	captureResponses(t)
	sw, evt, qdir, _ := deadlineInfectedEvent(t)
	journal := strings.TrimSuffix(evt.path, "-D") + "-J"
	if err := os.WriteFile(journal, []byte("recipient@example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	evt.guard.expire()
	sw.handleSpoolEventSafe(evt)
	assertDeadlineSpoolIntact(t, evt.path, qdir)
	if data, err := os.ReadFile(journal); err != nil || string(data) != "recipient@example.com\n" {
		t.Fatalf("delivery journal changed: %q, %v", data, err)
	}
}

func assertDeadlineSpoolIntact(t *testing.T, body, qdir string) {
	t.Helper()
	for _, path := range []string{body, strings.TrimSuffix(body, "-D") + "-H"} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("unsafe quarantine moved spool file %s: %v", path, err)
		}
	}
	if entries, err := os.ReadDir(qdir); err != nil || len(entries) != 0 {
		t.Errorf("unsafe quarantine created entries: %v, %v", entries, err)
	}
}

func TestSpoolDeadlineFinishJoinsTimerWrite(t *testing.T) {
	sw, _ := testHoldWatcher(t)
	fd := openSpoolFD(t)
	orig := spoolWriteResponse
	t.Cleanup(func() { spoolWriteResponse = orig })
	writing, release := make(chan struct{}), make(chan struct{})
	spoolWriteResponse = func(_ *SpoolWatcher, eventFD int32, response uint32) {
		if eventFD != fd || response != FAN_ALLOW {
			t.Errorf("timer verdict = (%d, %d)", eventFD, response)
		}
		close(writing)
		<-release
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			t.Errorf("event closed before its verdict write finished: %v", err)
		}
	}
	guard := sw.newHoldGuard(fd, true)
	var wg sync.WaitGroup
	wg.Go(guard.expire)
	<-writing
	finished := make(chan struct{})
	wg.Go(func() { guard.finish(FAN_DENY); close(finished) })
	select {
	case <-finished:
		t.Error("finish returned while the timer still owned the response fd")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	assertFDClosed(t, int(fd), "timer joined by finish")
}

func TestSpoolDeadlineConcurrentFinishAndExpiryAnswerOnce(t *testing.T) {
	responses := captureResponses(t)
	sw, _ := testHoldWatcher(t)
	for range 100 {
		fd := openSpoolFD(t)
		guard := sw.newHoldGuard(fd, true)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() { <-start; guard.expire() })
		wg.Go(func() { <-start; guard.finish(FAN_DENY) })
		wg.Go(func() { <-start; guard.finish(FAN_ALLOW) })
		close(start)
		wg.Wait()
		assertFDClosed(t, int(fd), "concurrent finish")
	}
	if got := responses(); len(got) != 100 {
		t.Fatalf("responses = %d, want one for each of 100 events", len(got))
	}
}

func TestSpoolDeadlineShutdownDrainsGuardedEventsOnce(t *testing.T) {
	responses := captureResponses(t)
	sw, _ := testHoldWatcher(t)
	sw.fdClosed, sw.pipeClosed, sw.runActive = 1, 1, 1
	sw.scanCh = make(chan spoolEvent, 4)
	var fds []int32
	for range 4 {
		fd := openSpoolFD(t)
		fds = append(fds, fd)
		sw.dispatchEvent(fd, int32(os.Getpid()+1))
	}
	for i := range 4 {
		evt := <-sw.scanCh
		if i%2 == 0 {
			evt.guard.expire()
		}
		sw.scanCh <- evt
	}
	sw.Stop()
	sw.wg.Add(1)
	go sw.scanWorker()
	sw.drainAndClose()
	got := responses()
	if len(got) != len(fds) {
		t.Fatalf("shutdown responses = %+v, want one per event", got)
	}
	for _, fd := range fds {
		count := 0
		for _, r := range got {
			if r.fd == fd && r.response == FAN_ALLOW {
				count++
			}
		}
		if count != 1 {
			t.Errorf("fd %d received %d ALLOW responses", fd, count)
		}
		assertFDClosed(t, int(fd), "shutdown drain")
	}
}

func TestSpoolDeadlineBypassRecoveryResumesScanning(t *testing.T) {
	responses := captureResponses(t)
	sw, _ := testHoldWatcher(t)
	sw.holds.bypassUntil = time.Now().Add(-time.Second)
	fd := openSpoolFD(t)
	sw.dispatchEvent(fd, int32(os.Getpid()+1))
	select {
	case evt := <-sw.scanCh:
		if len(responses()) != 0 {
			t.Error("recovered event was answered before scanning")
		}
		evt.finish(sw, FAN_DENY)
	default:
		t.Fatal("cooldown expired but scanning did not resume")
	}
	if got := responses(); len(got) != 1 || got[0].response != FAN_DENY {
		t.Fatalf("recovered scan lost its verdict: %+v", got)
	}
}

type deadlineBarrierScanner struct {
	started chan struct{}
	release chan struct{}
}

func (s deadlineBarrierScanner) Name() string    { return "deadline-test" }
func (s deadlineBarrierScanner) Available() bool { return true }
func (s deadlineBarrierScanner) Scan(string) (emailav.Verdict, error) {
	s.started <- struct{}{}
	<-s.release
	return emailav.Verdict{Infected: true, Signature: "test-infected"}, nil
}

func TestSpoolDeadlineConcurrentLateQuarantineMovesMessageOnce(t *testing.T) {
	responses := captureResponses(t)
	sw, first, qdir, _ := deadlineInfectedEvent(t)
	fd, err := unix.Open(first.path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	second := spoolEvent{path: first.path, fd: fd, needResp: true, guard: sw.newHoldGuard(int32(fd), true)}
	t.Cleanup(func() { second.finish(sw, FAN_ALLOW) })
	want := make(map[string]string)
	for _, suffix := range []string{"-H", "-D"} {
		data, readErr := os.ReadFile(strings.TrimSuffix(first.path, "-D") + suffix)
		if readErr != nil {
			t.Fatal(readErr)
		}
		want[suffix] = string(data)
	}
	scanner := deadlineBarrierScanner{started: make(chan struct{}, 2), release: make(chan struct{})}
	sw.orchestrator = emailav.NewOrchestrator([]emailav.Scanner{scanner}, 5*time.Second)
	var wg sync.WaitGroup
	wg.Go(func() { sw.handleSpoolEventSafe(first) })
	wg.Go(func() { sw.handleSpoolEventSafe(second) })
	release := sync.OnceFunc(func() { close(scanner.release) })
	t.Cleanup(func() { release(); wg.Wait() })
	for range 2 {
		select {
		case <-scanner.started:
		case <-time.After(2 * time.Second):
			t.Fatal("both scans must start before either can quarantine")
		}
	}
	first.guard.expire()
	second.guard.expire()
	release()
	wg.Wait()
	if got := responses(); len(got) != 2 || got[0].response != FAN_ALLOW || got[1].response != FAN_ALLOW {
		t.Fatalf("late concurrent verdicts = %+v, want two initial ALLOWs only", got)
	}
	entries, err := os.ReadDir(qdir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "deadline-message" {
		t.Fatalf("quarantine entries = %v, %v", entries, err)
	}
	for suffix, contents := range want {
		data, err := os.ReadFile(filepath.Join(qdir, "deadline-message", "deadline-message"+suffix))
		if err != nil || string(data) != contents {
			t.Errorf("concurrent quarantine corrupted %s: %v", suffix, err)
		}
		if _, err := os.Stat(strings.TrimSuffix(first.path, "-D") + suffix); !os.IsNotExist(err) {
			t.Errorf("spool file %s remained after quarantine: %v", suffix, err)
		}
	}
}
