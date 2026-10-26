//go:build linux

package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailav"
	emime "github.com/pidginhost/csm/internal/mime"
	"github.com/pidginhost/csm/internal/workerproc"
)

// inProcessExtractor parses in the test process, as the worker would. Tests
// that exercise scanning rather than isolation use it.
type inProcessExtractor struct{ dir string }

func (inProcessExtractor) Size() int { return 1 }

func (e inProcessExtractor) Extract(_ context.Context, _ int, header, body *os.File, limits emime.Limits) (*emime.ExtractionResult, error) {
	limits.TempDir = e.dir
	return emime.ParseSpoolFiles(header, body, limits)
}

// extractCall is what one Extract call was given.
type extractCall struct {
	slot           int
	header, body   unix.Stat_t
	headerFile     *os.File
	bodyFile       *os.File
	bodyFD         int
	bodyCloseOnExe bool
}

// recordingExtractor records every call and answers with extract, or with an
// empty result.
type recordingExtractor struct {
	size    int
	extract func(ctx context.Context, slot int) (*emime.ExtractionResult, error)

	mu    sync.Mutex
	calls []extractCall
}

func (e *recordingExtractor) Size() int { return e.size }

func (e *recordingExtractor) Extract(ctx context.Context, slot int, header, body *os.File, _ emime.Limits) (*emime.ExtractionResult, error) {
	c := extractCall{slot: slot, headerFile: header, bodyFile: body, bodyFD: int(body.Fd())}
	_ = unix.Fstat(int(header.Fd()), &c.header)
	_ = unix.Fstat(c.bodyFD, &c.body)
	if flags, err := unix.FcntlInt(body.Fd(), unix.F_GETFD, 0); err == nil {
		c.bodyCloseOnExe = flags&unix.FD_CLOEXEC != 0
	}
	e.mu.Lock()
	e.calls = append(e.calls, c)
	e.mu.Unlock()
	if e.extract != nil {
		return e.extract(ctx, slot)
	}
	return &emime.ExtractionResult{}, nil
}

func (e *recordingExtractor) recorded() []extractCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]extractCall(nil), e.calls...)
}

func extractWatcher(failMode string, ex mailExtractor) (*SpoolWatcher, chan alert.Finding) {
	cfg := &config.Config{}
	cfg.EmailAV.MaxAttachmentSize = 1024 * 1024
	cfg.EmailAV.MaxArchiveDepth = 1
	cfg.EmailAV.MaxArchiveFiles = 10
	cfg.EmailAV.MaxExtractionSize = 10 * 1024 * 1024
	cfg.EmailAV.FailMode = failMode
	ch := make(chan alert.Finding, 32)
	return &SpoolWatcher{
		cfg:          cfg,
		alertCh:      ch,
		orchestrator: emailav.NewOrchestrator([]emailav.Scanner{cleanScanner{}}, 5*time.Second),
		extractor:    ex,
		stopCh:       make(chan struct{}),
		fdClosed:     1,
	}, ch
}

// bodyEvent is a permission event for the message's -D file, with the event
// descriptor open on it as fanotify gives it.
func bodyEvent(t *testing.T, dir, msgID string) spoolEvent {
	t.Helper()
	path := filepath.Join(dir, msgID+"-D")
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	return spoolEvent{path: path, fd: fd, needResp: true}
}

func takeFindings(ch chan alert.Finding) []alert.Finding {
	var out []alert.Finding
	for {
		select {
		case f := <-ch:
			out = append(out, f)
		default:
			return out
		}
	}
}

func findingsFor(fs []alert.Finding, check string) []alert.Finding {
	var out []alert.Finding
	for _, f := range fs {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func wantResponse(failMode string) uint32 {
	if failMode == "tempfail" {
		return FAN_DENY
	}
	return FAN_ALLOW
}

// The worker is handed whatever -H the daemon opens, so a -H on another
// filesystem than the spool body is refused.
func TestSpoolHeaderOpenRefusesOtherDevice(t *testing.T) {
	shm := t.TempDir()
	if _, err := os.Stat("/dev/shm"); err == nil {
		if d, mkErr := os.MkdirTemp("/dev/shm", "csm-hdr-"); mkErr == nil {
			shm = d
			t.Cleanup(func() { _ = os.RemoveAll(d) })
		}
	}
	bodyDir := t.TempDir()
	var hs, bs unix.Stat_t
	if unix.Stat(shm, &hs) != nil || unix.Stat(bodyDir, &bs) != nil || hs.Dev == bs.Dev {
		t.Skip("no second filesystem for the header")
	}
	header := filepath.Join(shm, "1aBcDe-XDEV00-XX-H")
	if err := os.WriteFile(header, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := os.Create(filepath.Join(bodyDir, "1aBcDe-XDEV00-XX-D"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = body.Close() }()
	f, err := openSpoolHeader(header, int(body.Fd()))
	if err == nil {
		_ = f.Close()
		t.Fatal("openSpoolHeader accepted a -H on another filesystem")
	}
	if !strings.Contains(err.Error(), "not on the spool filesystem") {
		t.Fatalf("error = %v, want the filesystem refusal", err)
	}
}

// A close-on-exec body duplicate does not protect the original event fd:
// queued events must not be inherited by a worker's systemd-run client.
func TestSpoolWatcherRequestsCloseOnExecEvents(t *testing.T) {
	real := spoolFanotifyInit
	t.Cleanup(func() { spoolFanotifyInit = real })
	var eventFlags []uint
	spoolFanotifyInit = func(_, flags uint) (int, error) {
		eventFlags = append(eventFlags, flags)
		return -1, unix.EPERM
	}
	if _, err := NewSpoolWatcher(&config.Config{}, nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("failed fanotify initialization succeeded")
	}
	if len(eventFlags) != 2 {
		t.Fatalf("fanotify attempts = %d, want permission and notification modes", len(eventFlags))
	}
	for i, flags := range eventFlags {
		if flags&unix.O_CLOEXEC == 0 {
			t.Errorf("attempt %d leaves event descriptors inheritable: flags %#x", i, flags)
		}
	}
}

// A -H that is a link, a FIFO or a directory is never handed to the worker:
// a link could point anywhere and a FIFO would hang it.
func TestSpoolHeaderOpenRefusesNonRegular(t *testing.T) {
	cases := []struct {
		name string
		make func(t *testing.T, header string)
	}{
		{"symlink", func(t *testing.T, header string) {
			real := header + ".real"
			if err := os.Rename(header, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, header); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo", func(t *testing.T, header string) {
			if err := os.Remove(header); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(header, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory", func(t *testing.T, header string) {
			if err := os.Remove(header); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(header, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			msgID := "1aBcDe-HDRBAD-XX"
			buildMinimalEximSpool(t, dir, msgID)
			header := filepath.Join(dir, msgID+"-H")
			tc.make(t, header)

			body, err := os.Open(filepath.Join(dir, msgID+"-D"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = body.Close() }()
			if f, openErr := openSpoolHeader(header, int(body.Fd())); openErr == nil {
				_ = f.Close()
				t.Fatal("openSpoolHeader accepted a non-regular -H")
			}

			for _, mode := range []string{"tempfail", "open"} {
				responses := captureResponses(t)
				ex := &recordingExtractor{size: 1}
				sw, ch := extractWatcher(mode, ex)
				sw.handleSpoolEvent(bodyEvent(t, dir, msgID))
				if got := responses(); len(got) != 1 || got[0].response != wantResponse(mode) {
					t.Fatalf("%s: responses %+v", mode, got)
				}
				if n := len(ex.recorded()); n != 0 {
					t.Fatalf("%s: extractor called %d times", mode, n)
				}
				if len(findingsFor(takeFindings(ch), "email_av_parse_error")) != 1 {
					t.Fatalf("%s: no email_av_parse_error", mode)
				}
			}
		})
	}
}

// The worker gets the spool files as descriptors: the -H the daemon opened
// and a close-on-exec duplicate of the event descriptor for -D.
func TestSpoolExtractPassesDescriptorsNotPaths(t *testing.T) {
	captureResponses(t)
	dir := t.TempDir()
	msgID := "1aBcDe-DESC-XX"
	buildMinimalEximSpool(t, dir, msgID)
	ex := &recordingExtractor{size: 1}
	sw, _ := extractWatcher("open", ex)
	evt := bodyEvent(t, dir, msgID)
	sw.handleSpoolEvent(evt)

	calls := ex.recorded()
	if len(calls) != 1 {
		t.Fatalf("extractor calls = %d", len(calls))
	}
	var h, d unix.Stat_t
	if err := unix.Stat(filepath.Join(dir, msgID+"-H"), &h); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(filepath.Join(dir, msgID+"-D"), &d); err != nil {
		t.Fatal(err)
	}
	c := calls[0]
	if c.header.Ino != h.Ino || c.header.Dev != h.Dev || c.body.Ino != d.Ino || c.body.Dev != d.Dev {
		t.Fatalf("extractor got other files: header ino %d want %d, body ino %d want %d", c.header.Ino, h.Ino, c.body.Ino, d.Ino)
	}
	if c.bodyFD == evt.fd || !c.bodyCloseOnExe {
		t.Fatalf("body fd %d (event fd %d), close-on-exec %v", c.bodyFD, evt.fd, c.bodyCloseOnExe)
	}
}

// A hung worker costs one deadline, not a scan slot forever, and the message
// follows the fail mode as a partial scan.
func TestSpoolExtractWorkerHangIsPartial(t *testing.T) {
	real := spoolExtractTimeout
	spoolExtractTimeout = 100 * time.Millisecond
	t.Cleanup(func() { spoolExtractTimeout = real })
	for _, mode := range []string{"tempfail", "open"} {
		responses := captureResponses(t)
		dir := t.TempDir()
		msgID := "1aBcDe-HANG-XX"
		buildMinimalEximSpool(t, dir, msgID)
		ex := &recordingExtractor{size: 1, extract: func(ctx context.Context, _ int) (*emime.ExtractionResult, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}
		sw, ch := extractWatcher(mode, ex)
		start := time.Now()
		sw.handleSpoolEvent(bodyEvent(t, dir, msgID))
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("%s: hung extraction held the event %s", mode, elapsed)
		}
		if got := responses(); len(got) != 1 || got[0].response != wantResponse(mode) {
			t.Fatalf("%s: responses %+v", mode, got)
		}
		fs := takeFindings(ch)
		failed := findingsFor(fs, "email_av_parse_worker_failed")
		if len(failed) != 1 || !strings.Contains(failed[0].Message, "parse worker timed out") || !strings.Contains(failed[0].Message, msgID) {
			t.Fatalf("%s: parse worker findings %+v", mode, failed)
		}
		if d := findingsFor(fs, "email_av_degraded"); len(d) != 1 || !strings.Contains(d[0].Message, "parse worker timed out") {
			t.Fatalf("%s: degraded findings %+v", mode, d)
		}
	}
}

// Each scan goroutine owns one slot: parts are charged to the memory cgroup
// of the worker that wrote them, so no two scans may share a worker.
func TestSpoolExtractUsesOwnSlot(t *testing.T) {
	const n = 3
	arrived := make(chan int, n)
	release := make(chan struct{})
	ex := &recordingExtractor{size: n, extract: func(_ context.Context, slot int) (*emime.ExtractionResult, error) {
		arrived <- slot
		<-release
		return &emime.ExtractionResult{}, nil
	}}
	sw, _ := extractWatcher("open", ex)
	sw.cfg.EmailAV.ScanConcurrency = 1 // the extractor's size wins
	sw.scanCh = make(chan spoolEvent, n)
	sw.initQueueHealth()
	if got := sw.startScanWorkers(); got != n {
		t.Fatalf("started %d scan workers, want %d", got, n)
	}
	dir := t.TempDir()
	for i := range n {
		msgID := fmt.Sprintf("1aBcDe-SLOT%d-XX", i)
		// One message per sender scans at a time; use three senders.
		buildSourceSpool(t, dir, msgID, fmt.Sprintf("192.0.2.%d", 10+i))
		evt := bodyEvent(t, dir, msgID)
		evt.needResp = false
		evt.queueTicket = sw.scannerHealth.Begin(time.Now())
		sw.scanCh <- evt
	}
	seen := map[int]bool{}
	for range n {
		select {
		case slot := <-arrived:
			seen[slot] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d events reached a worker concurrently: %v", len(seen), seen)
		}
	}
	close(release)
	close(sw.scanCh)
	sw.wg.Wait()
	for slot := range n {
		if !seen[slot] {
			t.Fatalf("slots used %v, want each of 0..%d once", seen, n-1)
		}
	}
}

// fakeWorkerProc is an in-process worker for real supervisor failures.
type fakeWorkerProc struct {
	parent, child *net.UnixConn
	done          chan struct{}
	once          sync.Once
	oom           bool
}

func (p *fakeWorkerProc) Conn() *net.UnixConn { return p.parent }
func (p *fakeWorkerProc) Kill() error {
	p.once.Do(func() { _ = p.child.Close(); close(p.done) })
	return nil
}
func (p *fakeWorkerProc) Done() <-chan struct{} { return p.done }
func (p *fakeWorkerProc) PID() int              { return 0 }
func (p *fakeWorkerProc) Retire() bool          { return false }
func (p *fakeWorkerProc) OOMKilled() bool       { return p.oom }

func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "socketpair")
		defer func() { _ = f.Close() }()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	return conn(fds[0]), conn(fds[1])
}

// workerFailure returns a real failed Call with the given reason, from a
// supervisor over an in-process worker that misbehaves accordingly.
func workerFailure(t *testing.T, reason string) error {
	t.Helper()
	lim := workerproc.Limits{MaxFrameBytes: 1 << 16}
	sup, err := workerproc.New(workerproc.Config{
		Name: "test worker",
		Launch: func(context.Context) (workerproc.Process, error) {
			parent, child := unixPair(t)
			p := &fakeWorkerProc{parent: parent, child: child, done: make(chan struct{}), oom: reason == workerproc.ReasonOOM}
			go func() {
				if _, _, recvErr := workerproc.ReceiveFrame(child, lim); recvErr != nil {
					return
				}
				switch reason {
				case workerproc.ReasonProtocol:
					_ = workerproc.SendFrame(child, workerproc.Frame{Payload: []byte(`{}`)}, nil, lim.MaxFrameBytes)
				case workerproc.ReasonCrash, workerproc.ReasonOOM:
					_ = child.Close()
				}
				// ReasonTimeout: never answer.
			}()
			return p, nil
		},
		Timeout: 100 * time.Millisecond,
		Limits:  lim,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Stop() })
	_, _, err = sup.Call(context.Background(), workerproc.Frame{Op: "x"}, nil, func(workerproc.Frame, []*os.File) (bool, error) {
		return false, errors.New("reply rejected")
	})
	if got := workerproc.FailureReason(err); got != reason {
		t.Fatalf("failure reason = %q, want %q (%v)", got, reason, err)
	}
	return err
}

func TestSpoolExtractErrorMapping(t *testing.T) {
	cases := []struct {
		name     string
		err      func(t *testing.T) error
		nilEx    bool
		reason   string
		findings map[string]alert.Severity
	}{
		{"spawn", func(*testing.T) error { return fmt.Errorf("%w: systemd-run missing", workerproc.ErrSpawn) }, false,
			"parse isolation unavailable", map[string]alert.Severity{"email_av_isolation_unavailable": alert.Critical}},
		{"breaker", func(*testing.T) error { return fmt.Errorf("%w: 3 failures in a row", workerproc.ErrBreakerOpen) }, false,
			"parse worker failing repeatedly", map[string]alert.Severity{"email_av_isolation_unavailable": alert.Critical}},
		{"no extractor", nil, true,
			"parse isolation unavailable", map[string]alert.Severity{"email_av_isolation_unavailable": alert.Critical}},
		{"timeout", func(t *testing.T) error { return workerFailure(t, workerproc.ReasonTimeout) }, false,
			"parse worker timed out", map[string]alert.Severity{"email_av_parse_worker_failed": alert.Warning}},
		{"oom", func(t *testing.T) error { return workerFailure(t, workerproc.ReasonOOM) }, false,
			"parse worker ran out of memory", map[string]alert.Severity{"email_av_parse_worker_failed": alert.Warning}},
		{"crash", func(t *testing.T) error { return workerFailure(t, workerproc.ReasonCrash) }, false,
			"parse worker crashed", map[string]alert.Severity{"email_av_parse_worker_failed": alert.Warning}},
		{"protocol", func(t *testing.T) error { return workerFailure(t, workerproc.ReasonProtocol) }, false,
			"parse worker reply rejected", map[string]alert.Severity{"email_av_parse_worker_failed": alert.Warning, "email_av_parse_worker_rejected": alert.Critical}},
	}
	others := []string{"email_av_isolation_unavailable", "email_av_parse_worker_failed", "email_av_parse_worker_rejected", "email_av_parse_error"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ex mailExtractor
			if !tc.nilEx {
				failure := tc.err(t)
				ex = &recordingExtractor{size: 1, extract: func(context.Context, int) (*emime.ExtractionResult, error) { return nil, failure }}
			}
			for _, mode := range []string{"tempfail", "open"} {
				responses := captureResponses(t)
				dir := t.TempDir()
				msgID := "1aBcDe-MAP-XX"
				buildMinimalEximSpool(t, dir, msgID)
				sw, ch := extractWatcher(mode, ex)
				sw.handleSpoolEvent(bodyEvent(t, dir, msgID))
				if got := responses(); len(got) != 1 || got[0].response != wantResponse(mode) {
					t.Fatalf("%s: responses %+v", mode, got)
				}
				fs := takeFindings(ch)
				if d := findingsFor(fs, "email_av_degraded"); len(d) != 1 || !strings.Contains(d[0].Message, fmt.Sprintf("(%q)", tc.reason)) {
					t.Fatalf("%s: degraded findings %+v, want reason %q", mode, d, tc.reason)
				}
				for _, check := range others {
					got := findingsFor(fs, check)
					sev, want := tc.findings[check]
					if !want {
						if len(got) != 0 {
							t.Fatalf("%s: unexpected %s: %+v", mode, check, got)
						}
						continue
					}
					if len(got) != 1 || got[0].Severity != sev || !strings.Contains(got[0].Message, msgID) {
						t.Fatalf("%s: %s findings %+v, want one at %v naming the message", mode, check, got, sev)
					}
				}
			}
		})
	}
}

func TestSpoolExtractFindingRateLimits(t *testing.T) {
	protocol := workerFailure(t, workerproc.ReasonProtocol)
	spawn := fmt.Errorf("%w: no systemd-run", workerproc.ErrSpawn)
	var next error
	ex := &recordingExtractor{size: 1, extract: func(context.Context, int) (*emime.ExtractionResult, error) { return nil, next }}
	sw, ch := extractWatcher("open", ex)
	captureResponses(t)
	dir := t.TempDir()
	for i, err := range []error{protocol, protocol, spawn, spawn} {
		next = err
		msgID := fmt.Sprintf("1aBcDe-RATE%d-XX", i)
		buildMinimalEximSpool(t, dir, msgID)
		sw.handleSpoolEvent(bodyEvent(t, dir, msgID))
	}
	fs := takeFindings(ch)
	if n := len(findingsFor(fs, "email_av_parse_worker_rejected")); n != 1 {
		t.Fatalf("rejected findings = %d, want 1 an hour", n)
	}
	if n := len(findingsFor(fs, "email_av_isolation_unavailable")); n != 1 {
		t.Fatalf("isolation findings = %d, want 1 an hour", n)
	}
	if n := len(findingsFor(fs, "email_av_parse_worker_failed")); n != 1 {
		t.Fatalf("worker failed findings = %d, want 1 a minute", n)
	}
}

// The watcher has already released pending opens on shutdown. Queued events
// need closing, not new worker launches or outage findings during the drain.
func TestSpoolExtractShutdownDrainsWithoutParsing(t *testing.T) {
	responses := captureResponses(t)
	dir := t.TempDir()
	msgID := "1aBcDe-STOP-XX"
	buildMinimalEximSpool(t, dir, msgID)
	ex := &recordingExtractor{size: 1, extract: func(context.Context, int) (*emime.ExtractionResult, error) {
		return nil, workerproc.ErrStopped
	}}
	sw, ch := extractWatcher("tempfail", ex)
	d := &Daemon{stopCh: make(chan struct{})}
	d.setSpoolWatcher(sw)
	close(d.stopCh)
	close(sw.stopCh)
	evt := bodyEvent(t, dir, msgID)
	sw.handleSpoolEventSafe(evt)
	if calls := ex.recorded(); len(calls) != 0 {
		t.Fatalf("shutdown launched %d extractions", len(calls))
	}
	if fs := takeFindings(ch); len(fs) != 0 {
		t.Fatalf("shutdown reported an outage: %+v", fs)
	}
	if got := responses(); len(got) != 1 || got[0].response != FAN_ALLOW {
		t.Fatalf("shutdown responses %+v, want one release", got)
	}
	if _, err := unix.FcntlInt(uintptr(evt.fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("queued event descriptor survived shutdown: %v", err)
	}
}

// A broken fanotify instance releases opens too, but its replacement must
// still wait for queued mail to be scanned before reusing the pool slots.
func TestSpoolExtractWatcherRestartStillDrains(t *testing.T) {
	responses := captureResponses(t)
	dir := t.TempDir()
	msgID := "1aBcDe-RESTART-XX"
	buildMinimalEximSpool(t, dir, msgID)
	ex := &recordingExtractor{size: 1}
	sw, ch := extractWatcher("tempfail", ex)
	d := &Daemon{stopCh: make(chan struct{})}
	d.setSpoolWatcher(sw)
	close(sw.stopCh)
	sw.handleSpoolEventSafe(bodyEvent(t, dir, msgID))
	if calls := ex.recorded(); len(calls) != 1 {
		t.Fatalf("watcher restart discarded queued mail: %d extractions", len(calls))
	}
	if fs := takeFindings(ch); len(fs) != 0 {
		t.Fatalf("clean extraction during restart reported findings: %+v", fs)
	}
	if got := responses(); len(got) != 1 || got[0].response != FAN_ALLOW {
		t.Fatalf("restart responses %+v, want one release", got)
	}
}

type panicAvailableScanner struct{ cleanScanner }

func (panicAvailableScanner) Available() bool { panic("scanner availability failed") }

func TestSpoolExtractClosesDescriptorsOnEveryExit(t *testing.T) {
	for _, outcome := range []string{"clean", "partial", "extract error", "extract panic", "scan panic"} {
		t.Run(outcome, func(t *testing.T) {
			responses := captureResponses(t)
			dir := t.TempDir()
			msgID := "1aBcDe-CLOSE-XX"
			buildMinimalEximSpool(t, dir, msgID)
			var part *os.File
			ex := &recordingExtractor{size: 1, extract: func(context.Context, int) (*emime.ExtractionResult, error) {
				switch outcome {
				case "extract error":
					return nil, workerproc.ErrSpawn
				case "extract panic":
					panic("extraction failed")
				}
				part = memfdPart(t, "body")
				t.Cleanup(func() { _ = part.Close() })
				return &emime.ExtractionResult{Partial: outcome == "partial",
					Parts: []emime.ExtractedPart{{Filename: "part.bin", Size: 4, File: part}}}, nil
			}}
			sw, _ := extractWatcher("tempfail", ex)
			if outcome == "scan panic" {
				sw.orchestrator = emailav.NewOrchestrator([]emailav.Scanner{panicAvailableScanner{}}, time.Second)
			}
			evt := bodyEvent(t, dir, msgID)
			sw.handleSpoolEventSafe(evt)
			calls := ex.recorded()
			if len(calls) != 1 {
				t.Fatalf("extractions = %d, want 1", len(calls))
			}
			for name, f := range map[string]*os.File{"header": calls[0].headerFile, "body": calls[0].bodyFile, "part": part} {
				if f != nil && f.Fd() != ^uintptr(0) {
					t.Errorf("%s descriptor left open", name)
				}
			}
			if _, err := unix.FcntlInt(uintptr(evt.fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Errorf("event descriptor left open: %v", err)
			}
			if got := responses(); len(got) != 1 {
				t.Errorf("event received %d responses, want 1", len(got))
			}
		})
	}
}

// markerScanner flags any part holding testMarker, standing in for an engine.
type markerScanner struct{}

const testMarker = "csm-test-infected-part"

func (markerScanner) Name() string    { return "stub-marker" }
func (markerScanner) Available() bool { return true }
func (markerScanner) Scan(p emailav.Part) (emailav.Verdict, error) {
	data, err := io.ReadAll(io.NewSectionReader(p.File, 0, p.Size))
	if err != nil {
		return emailav.Verdict{}, err
	}
	if bytes.Contains(data, []byte(testMarker)) {
		return emailav.Verdict{Infected: true, Signature: "Test.Marker", Severity: "critical"}, nil
	}
	return emailav.Verdict{}, nil
}

func memfdPart(t *testing.T, data string) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate("part", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "part")
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
	return f
}

// Parts from the worker go through the engines and quarantine as before, and
// are closed when the scan ends.
func TestSpoolExtractScansReturnedParts(t *testing.T) {
	responses := captureResponses(t)
	dir := t.TempDir()
	msgID := "1aBcDe-PARTS-XX"
	buildMinimalEximSpool(t, dir, msgID)
	part := memfdPart(t, "prefix "+testMarker+" suffix")
	ex := &recordingExtractor{size: 1, extract: func(context.Context, int) (*emime.ExtractionResult, error) {
		st, err := part.Stat()
		if err != nil {
			return nil, err
		}
		return &emime.ExtractionResult{
			From: "sender@example.com", To: []string{"recipient@example.com"}, Subject: "parts", Direction: "inbound",
			Parts: []emime.ExtractedPart{{Filename: "file.bin", ContentType: "application/octet-stream", Size: st.Size(), File: part}},
		}, nil
	}}
	sw, ch := extractWatcher("open", ex)
	sw.orchestrator = emailav.NewOrchestrator([]emailav.Scanner{markerScanner{}}, 5*time.Second)
	sw.quarantine = emailav.NewQuarantine(t.TempDir())
	sw.cfg.EmailAV.QuarantineInfected = true
	var quarantined []string
	sw.onQuarantined = func(_ time.Time, id string) { quarantined = append(quarantined, id) }

	sw.handleSpoolEvent(bodyEvent(t, dir, msgID))
	if got := responses(); len(got) != 1 || got[0].response != FAN_DENY {
		t.Fatalf("responses %+v, want deny after quarantine", got)
	}
	if len(quarantined) != 1 || quarantined[0] != msgID {
		t.Fatalf("quarantined %v", quarantined)
	}
	if m := findingsFor(takeFindings(ch), "email_malware"); len(m) != 1 || !strings.Contains(m[0].Message, "Test.Marker") {
		t.Fatalf("malware findings %+v", m)
	}
	if part.Fd() != ^uintptr(0) {
		t.Fatal("part descriptor left open after the scan")
	}
}

// The attachment staging directory of earlier versions is removed, and a
// link in its place is removed without following it.
func TestSpoolWatcherRemovesLegacyEmailAVTempDir(t *testing.T) {
	state := t.TempDir()
	legacy := filepath.Join(state, "emailav-tmp")
	if err := os.Mkdir(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "csm-part-1"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	removeLegacyEmailAVTempDir(state)
	if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy directory survived: %v", err)
	}

	target := t.TempDir()
	kept := filepath.Join(target, "keep")
	if err := os.WriteFile(kept, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, legacy); err != nil {
		t.Fatal(err)
	}
	removeLegacyEmailAVTempDir(state)
	if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy link survived: %v", err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("link target was followed: %v", err)
	}
	removeLegacyEmailAVTempDir(state) // absent: nothing to do
}
