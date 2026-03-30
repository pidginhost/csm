//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/emailav"
	emime "github.com/pidginhost/cpanel-security-monitor/internal/mime"
)

// fanotify constants for permission events (not in Go stdlib).
const (
	FAN_CLASS_CONTENT  = 0x00000004
	FAN_OPEN_PERM      = 0x00010000
	FAN_ALLOW          = 0x01
	FAN_DENY           = 0x02
	FAN_EVENT_ON_CHILD = 0x08000000
)

// fanotifyResponse is the struct written back to the fanotify fd
// to allow or deny a permission event.
type fanotifyResponse struct {
	Fd       int32
	Response uint32
}

const responseSize = int(unsafe.Sizeof(fanotifyResponse{}))

// SpoolWatcher monitors Exim spool directories for new messages using a
// dedicated fanotify instance with permission events (FAN_OPEN_PERM).
// It is completely separate from the FileMonitor.
type SpoolWatcher struct {
	fd             int
	cfg            *config.Config
	alertCh        chan<- alert.Finding
	orchestrator   *emailav.Orchestrator
	quarantine     *emailav.Quarantine
	permissionMode bool // true if using FAN_OPEN_PERM, false if fallback to FAN_CLOSE_WRITE

	scanCh    chan spoolEvent
	pipeFds   [2]int
	stopOnce  sync.Once
	drainOnce sync.Once
	stopCh    chan struct{}
	wg        sync.WaitGroup

	pipeClosed     int32 // atomic
	fdClosed       int32 // atomic — guards sw.fd against double-close
	degradedMu     sync.Mutex
	lastDegradedAt time.Time
}

type spoolEvent struct {
	path     string
	fd       int // fanotify event fd (for permission response)
	pid      int32
	needResp bool // true if permission event requiring response
}

// NewSpoolWatcher creates a dedicated fanotify instance for Exim spool scanning.
// Attempts FAN_CLASS_CONTENT with FAN_OPEN_PERM first; falls back to
// FAN_CLASS_NOTIF with FAN_CLOSE_WRITE if permission events are unavailable.
func NewSpoolWatcher(cfg *config.Config, alertCh chan<- alert.Finding, orch *emailav.Orchestrator, quar *emailav.Quarantine) (*SpoolWatcher, error) {
	sw := &SpoolWatcher{
		cfg:          cfg,
		alertCh:      alertCh,
		orchestrator: orch,
		quarantine:   quar,
		scanCh:       make(chan spoolEvent, 256),
		stopCh:       make(chan struct{}),
	}

	// Try permission-capable class first
	fd, err := unix.FanotifyInit(FAN_CLASS_CONTENT|FAN_CLOEXEC|FAN_NONBLOCK, unix.O_RDONLY)
	if err == nil {
		sw.fd = fd
		sw.permissionMode = true
		fmt.Fprintf(os.Stderr, "[%s] spool watcher: permission events enabled (FAN_OPEN_PERM)\n", ts())
	} else {
		// Fallback to notification-only
		fd, err = unix.FanotifyInit(FAN_CLASS_NOTIF|FAN_CLOEXEC|FAN_NONBLOCK, unix.O_RDONLY)
		if err != nil {
			return nil, fmt.Errorf("fanotify_init: %w (neither permission nor notification mode available)", err)
		}
		sw.fd = fd
		sw.permissionMode = false
		fmt.Fprintf(os.Stderr, "[%s] spool watcher: WARNING — permission events unavailable, using notification mode (small delivery race window possible)\n", ts())
	}

	// Mark spool directories
	spoolDirs := []string{"/var/spool/exim/input", "/var/spool/exim4/input"}
	var eventMask uint64
	if sw.permissionMode {
		eventMask = FAN_OPEN_PERM | FAN_EVENT_ON_CHILD
	} else {
		eventMask = FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD
	}

	marked := 0
	for _, dir := range spoolDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		// Use FAN_MARK_ADD (not FAN_MARK_MOUNT) to scope to the directory
		err := unix.FanotifyMark(sw.fd, FAN_MARK_ADD, eventMask, -1, dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] spool watcher: cannot watch %s: %v\n", ts(), dir, err)
			continue
		}
		marked++
		fmt.Fprintf(os.Stderr, "[%s] spool watcher: watching %s\n", ts(), dir)
	}

	if marked == 0 {
		unix.Close(sw.fd)
		return nil, fmt.Errorf("no Exim spool directories found to watch")
	}

	// Create pipe for stop signaling
	if err := unix.Pipe2(sw.pipeFds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		unix.Close(sw.fd)
		return nil, fmt.Errorf("creating pipe: %w", err)
	}

	return sw, nil
}

// Run starts the event loop and scanner workers. Blocks until Stop() is called.
func (sw *SpoolWatcher) Run() {
	// Start scanner workers
	concurrency := sw.cfg.EmailAV.ScanConcurrency
	if concurrency < 1 {
		concurrency = 4
	}
	for i := 0; i < concurrency; i++ {
		sw.wg.Add(1)
		go sw.scanWorker()
	}

	// Event loop
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] spool watcher: epoll_create: %v\n", ts(), err)
		return
	}
	defer unix.Close(epfd)

	unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, sw.fd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(sw.fd)})
	unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, sw.pipeFds[0], &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(sw.pipeFds[0])})

	events := make([]unix.EpollEvent, 16)
	buf := make([]byte, 4096)

	for {
		select {
		case <-sw.stopCh:
			sw.drainAndClose()
			return
		default:
		}

		n, err := unix.EpollWait(epfd, events, 500)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			select {
			case <-sw.stopCh:
				sw.drainAndClose()
				return
			default:
				continue
			}
		}

		for i := 0; i < n; i++ {
			if events[i].Fd == int32(sw.pipeFds[0]) {
				sw.drainAndClose()
				return
			}
			if events[i].Fd == int32(sw.fd) {
				sw.readEvents(buf)
			}
		}
	}
}

func (sw *SpoolWatcher) readEvents(buf []byte) {
	for {
		n, err := unix.Read(sw.fd, buf)
		if err != nil || n < metadataSize {
			return
		}

		offset := 0
		for offset+metadataSize <= n {
			meta := (*fanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			if meta.Fd < 0 {
				offset += int(meta.EventLen)
				continue
			}

			path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", meta.Fd))
			if err != nil {
				// Must respond even on error paths (permission mode)
				if sw.permissionMode {
					sw.writeResponse(meta.Fd, FAN_ALLOW)
				}
				unix.Close(int(meta.Fd))
				offset += int(meta.EventLen)
				continue
			}

			// Only process *-D files (message body)
			if !strings.HasSuffix(path, "-D") {
				if sw.permissionMode {
					sw.writeResponse(meta.Fd, FAN_ALLOW)
				}
				unix.Close(int(meta.Fd))
				offset += int(meta.EventLen)
				continue
			}

			// Send to scan workers — blocks if pool is full.
			// This is intentional: backpressure on Exim's delivery runner
			// is the correct behavior per the spec. Exim is designed to
			// handle delivery delays; unscanned delivery is not acceptable.
			evt := spoolEvent{
				path:     path,
				fd:       int(meta.Fd),
				pid:      meta.Pid,
				needResp: sw.permissionMode,
			}
			select {
			case sw.scanCh <- evt:
				// Worker will handle response and fd close
			case <-sw.stopCh:
				// Shutting down — allow and close
				if sw.permissionMode {
					sw.writeResponse(meta.Fd, FAN_ALLOW)
				}
				unix.Close(int(meta.Fd))
			}

			offset += int(meta.EventLen)
		}
	}
}

// scanWorker processes spool events: MIME parse, scan, quarantine/allow.
func (sw *SpoolWatcher) scanWorker() {
	defer sw.wg.Done()

	for {
		select {
		case <-sw.stopCh:
			return
		case evt, ok := <-sw.scanCh:
			if !ok {
				return
			}
			sw.handleSpoolEvent(evt)
		}
	}
}

func (sw *SpoolWatcher) handleSpoolEvent(evt spoolEvent) {
	// CRITICAL: deferred FAN_ALLOW — every code path must allow by default.
	// Only overridden to FAN_DENY on confirmed infection + successful quarantine.
	response := uint32(FAN_ALLOW)
	defer func() {
		if evt.needResp {
			sw.writeResponse(int32(evt.fd), response)
		}
		unix.Close(evt.fd)
	}()

	// Derive message ID: strip -D suffix and directory
	base := filepath.Base(evt.path)
	msgID := strings.TrimSuffix(base, "-D")
	spoolDir := filepath.Dir(evt.path)

	headerPath := filepath.Join(spoolDir, msgID+"-H")
	bodyPath := evt.path

	// MIME parse — fail-open on error
	limits := emime.Limits{
		MaxAttachmentSize: sw.cfg.EmailAV.MaxAttachmentSize,
		MaxArchiveDepth:   sw.cfg.EmailAV.MaxArchiveDepth,
		MaxArchiveFiles:   sw.cfg.EmailAV.MaxArchiveFiles,
		MaxExtractionSize: sw.cfg.EmailAV.MaxExtractionSize,
	}

	extraction, err := emime.ParseSpoolMessage(headerPath, bodyPath, limits)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] spool watcher: MIME parse error for %s: %v\n", ts(), msgID, err)
		sw.emitFinding("email_av_parse_error", alert.Warning, fmt.Sprintf("MIME parse failed for message %s: %v", msgID, err))
		return // fail-open: FAN_ALLOW via defer
	}

	// Clean up temp files when done
	defer func() {
		for _, p := range extraction.Parts {
			os.Remove(p.TempPath)
		}
	}()

	if len(extraction.Parts) == 0 {
		return // No attachments to scan — allow
	}

	// Scan
	result := sw.orchestrator.ScanParts(msgID, extraction.Parts, extraction.Partial)

	// Emit degraded/timeout findings for operator visibility
	if result.AllEnginesDown {
		sw.emitDegradedWarning(fmt.Sprintf("All AV engines unavailable — message %s delivered unscanned", msgID))
	}
	if len(result.TimedOutEngines) > 0 {
		sw.emitFinding("email_av_timeout", alert.Warning,
			fmt.Sprintf("Scan timeout for message %s on engine(s): %s", msgID, strings.Join(result.TimedOutEngines, ", ")))
	}

	if !result.Infected {
		return // Clean — allow
	}

	// Infected — attempt quarantine
	env := emailav.QuarantineEnvelope{
		From:      extraction.From,
		To:        extraction.To,
		Subject:   extraction.Subject,
		Direction: extraction.Direction,
	}

	if sw.cfg.EmailAV.QuarantineInfected {
		if err := sw.quarantine.QuarantineMessage(msgID, spoolDir, result, env); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] spool watcher: quarantine failed for %s: %v\n", ts(), msgID, err)
			// fail-open: allow delivery if quarantine fails
		} else {
			// Quarantine succeeded — deny the open so Exim can't deliver
			response = FAN_DENY
		}
	}

	// Emit alert finding
	sigNames := make([]string, len(result.Findings))
	for i, f := range result.Findings {
		sigNames[i] = fmt.Sprintf("%s(%s)", f.Signature, f.Engine)
	}
	msg := fmt.Sprintf("Malware detected in %s email from %s to %s: %s [subject: %s]",
		extraction.Direction, extraction.From, strings.Join(extraction.To, ","),
		strings.Join(sigNames, ", "), extraction.Subject)

	sw.emitFinding("email_malware", alert.Critical, msg)
}

func (sw *SpoolWatcher) writeResponse(fd int32, response uint32) {
	resp := fanotifyResponse{Fd: fd, Response: response}
	respBytes := (*[responseSize]byte)(unsafe.Pointer(&resp))[:]
	_, err := unix.Write(sw.fd, respBytes)
	if err != nil {
		// The kernel holds blocked processes until a response is written or
		// the fanotify fd is closed. A failed write means the fd is broken —
		// close it to release ALL pending permission events (fail-open),
		// then signal the event loop to exit so the daemon can restart us.
		fmt.Fprintf(os.Stderr, "[%s] spool watcher: FATAL — fanotify response write failed: %v — closing fd to release pending events\n", ts(), err)
		sw.closeFd()
		sw.Stop()
	}
}

// closeFd closes the fanotify fd exactly once, even if called from multiple paths.
func (sw *SpoolWatcher) closeFd() {
	if atomic.CompareAndSwapInt32(&sw.fdClosed, 0, 1) {
		unix.Close(sw.fd)
	}
}

func (sw *SpoolWatcher) emitFinding(check string, severity alert.Severity, message string) {
	select {
	case sw.alertCh <- alert.Finding{
		Severity: severity,
		Check:    check,
		Message:  message,
	}:
	default:
		// Alert channel full — drop
	}
}

// emitDegradedWarning emits an email_av_degraded finding, rate-limited to
// once per minute to avoid flooding the alert channel when clamd is down.
func (sw *SpoolWatcher) emitDegradedWarning(message string) {
	sw.degradedMu.Lock()
	if time.Since(sw.lastDegradedAt) < time.Minute {
		sw.degradedMu.Unlock()
		return
	}
	sw.lastDegradedAt = time.Now()
	sw.degradedMu.Unlock()
	sw.emitFinding("email_av_degraded", alert.Warning, message)
}

func (sw *SpoolWatcher) drainAndClose() {
	sw.drainOnce.Do(func() {
		close(sw.scanCh)
		sw.wg.Wait()
		sw.closeFd()
		if atomic.CompareAndSwapInt32(&sw.pipeClosed, 0, 1) {
			unix.Close(sw.pipeFds[0])
			unix.Close(sw.pipeFds[1])
		}
	})
}

// PermissionMode returns true if using FAN_OPEN_PERM, false if FAN_CLOSE_WRITE fallback.
func (sw *SpoolWatcher) PermissionMode() bool {
	return sw.permissionMode
}

// Stop signals the event loop to exit.
func (sw *SpoolWatcher) Stop() {
	sw.stopOnce.Do(func() {
		close(sw.stopCh)
		if atomic.LoadInt32(&sw.pipeClosed) == 0 {
			_, _ = unix.Write(sw.pipeFds[1], []byte{0})
		}
		sw.closeFd()
	})
}
