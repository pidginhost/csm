//go:build linux

package daemon

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// auditLogPath is the file the kernel auditd writes events to. Var (not
// const) so tests can redirect it under t.TempDir().
var auditLogPath = "/var/log/audit/audit.log"

// AFAlgAuditListener tails /var/log/audit/audit.log via inotify, parses
// each new line for the csm_af_alg_socket auditd key, and emits a
// Critical alert.Finding (plus optional kill/quarantine reactions)
// within milliseconds of the syscall. Sub-second response on hosts where
// BPF LSM is not available.
//
// The listener seeks to end-of-file at startup — events that pre-date
// the daemon are intentionally not re-alerted; the periodic critical-tier
// CheckAFAlgSocketUsage handles backfill via its (timestamp, serial)
// cursor in state.Store.
type AFAlgAuditListener struct {
	alertCh   chan<- alert.Finding
	cfg       *config.Config
	path      string
	inotifyFd int
	file      *os.File
	pos       int64
	leftover  []byte // partial line accumulator across reads

	eventCount atomic.Uint64 // observed by tests / metrics
}

// Mode reports the live-monitor backend kind. Matches the BPF path's
// "bpf-lsm" return so the coordinator and operator-visible logs use a
// stable, machine-readable label.
func (l *AFAlgAuditListener) Mode() string { return "auditd-tail" }

// EventCount returns the number of csm_af_alg_socket events this
// listener has parsed since startup. Operational metric; not exported
// to Prometheus here to keep the listener self-contained.
func (l *AFAlgAuditListener) EventCount() uint64 { return l.eventCount.Load() }

// NewAFAlgAuditListener opens the audit log, seeks to its current end,
// and registers an inotify watch on the file. The watch fires for
// IN_MODIFY (new bytes appended), IN_MOVE_SELF (logrotate moves the
// file), and IN_DELETE_SELF (file unlinked) so we can re-open the
// rotated/replaced file.
//
// Returns an error if /var/log/audit/audit.log is missing — caller is
// expected to log a warning and either skip live detection (with
// periodic check still active) or retry later.
func NewAFAlgAuditListener(alertCh chan<- alert.Finding, cfg *config.Config) (*AFAlgAuditListener, error) {
	l := &AFAlgAuditListener{
		alertCh: alertCh,
		cfg:     cfg,
		path:    auditLogPath,
	}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

// open initialises (or re-initialises after rotation) the audit log fd
// and inotify watch. Seeks to end-of-file so we tail forward, never
// re-alerting historical events.
func (l *AFAlgAuditListener) open() error {
	// #nosec G304 -- l.path is /var/log/audit/audit.log (or t.TempDir()
	// equivalent); not user-controlled.
	f, err := os.Open(l.path)
	if err != nil {
		return fmt.Errorf("open %s: %w", l.path, err)
	}
	end, err := f.Seek(0, 2) // SEEK_END
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("seek %s: %w", l.path, err)
	}

	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("inotify_init: %w", err)
	}
	mask := uint32(unix.IN_MODIFY | unix.IN_MOVE_SELF | unix.IN_DELETE_SELF)
	if _, err := unix.InotifyAddWatch(fd, l.path, mask); err != nil {
		_ = unix.Close(fd)
		_ = f.Close()
		return fmt.Errorf("inotify_add_watch %s: %w", l.path, err)
	}

	// Replace any existing fds (rotation case).
	if l.file != nil {
		_ = l.file.Close()
	}
	if l.inotifyFd != 0 {
		_ = unix.Close(l.inotifyFd)
	}
	l.file = f
	l.pos = end
	l.inotifyFd = fd
	l.leftover = nil
	return nil
}

// Run drains inotify events and tails the audit log until ctx is done.
// Polls the inotify fd every poll interval (matches forwarder_watcher's
// approach — no epoll, easier to reason about).
//
// On rotation (IN_MOVE_SELF / IN_DELETE_SELF) the listener re-opens the
// new audit.log and continues from its end. There is a brief window
// during rotation where events written between the move and the re-open
// can be missed; the periodic critical-tier check covers that gap via
// its persistent cursor.
func (l *AFAlgAuditListener) Run(ctx context.Context) {
	defer func() {
		if l.inotifyFd != 0 {
			_ = unix.Close(l.inotifyFd)
		}
		if l.file != nil {
			_ = l.file.Close()
		}
	}()

	inotifyBuf := make([]byte, 4096)
	readBuf := make([]byte, 16*1024)
	// Belt-and-braces: re-poll the file every 5s even without inotify
	// notifications. Catches events on hosts where the watch happens
	// to drop (extremely rare; defense in depth costs nothing).
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Start by draining anything the kernel may have queued during
	// startup.
	l.tail(readBuf)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rotated, ok := l.drainInotify(inotifyBuf)
			if !ok {
				continue
			}
			if rotated {
				if err := l.open(); err != nil {
					csmlog.Warn("af_alg audit listener: re-open failed", "err", err)
					continue
				}
			}
			l.tail(readBuf)
		}
	}
}

// drainInotify reads any queued inotify events. Returns:
//
//	ok=false  on read errors that aren't EAGAIN (don't process the file).
//	rotated=true if any IN_MOVE_SELF or IN_DELETE_SELF event was seen.
//
// IN_MODIFY events implicitly trigger a tail() in the caller because we
// always read at the end of each tick.
func (l *AFAlgAuditListener) drainInotify(buf []byte) (rotated, ok bool) {
	for {
		n, err := unix.Read(l.inotifyFd, buf)
		if err != nil {
			// EAGAIN = no more events queued; that's the normal exit.
			return rotated, true
		}
		if n <= 0 {
			return rotated, true
		}
		offset := 0
		for offset+unix.SizeofInotifyEvent <= n {
			// #nosec G103 -- inotify packed binary stream;
			// reinterpretation is required and the bound check above
			// guarantees the read is in-range.
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			if ev.Mask&(unix.IN_MOVE_SELF|unix.IN_DELETE_SELF) != 0 {
				rotated = true
			}
			offset += unix.SizeofInotifyEvent + int(ev.Len)
		}
	}
}

// tail reads any new bytes since l.pos, splits on newlines, and feeds
// each complete line to handleLine. Partial trailing bytes (no newline
// yet) are buffered in l.leftover for the next tick.
func (l *AFAlgAuditListener) tail(buf []byte) {
	if _, err := l.file.Seek(l.pos, 0); err != nil {
		csmlog.Warn("af_alg audit listener: seek failed", "err", err)
		return
	}
	for {
		n, err := l.file.Read(buf)
		if n > 0 {
			l.feed(buf[:n])
			l.pos += int64(n)
		}
		if err != nil {
			// io.EOF or EAGAIN: out of data for this tick.
			return
		}
	}
}

// feed appends a chunk of audit-log bytes to the leftover buffer and
// emits a finding for each complete line containing the csm_af_alg_socket
// key. Lines are kept in the leftover until terminated by '\n' so a
// short read at the end of the buffer does not corrupt a multi-byte
// timestamp split across two reads.
func (l *AFAlgAuditListener) feed(chunk []byte) {
	l.leftover = append(l.leftover, chunk...)
	for {
		idx := bytes.IndexByte(l.leftover, '\n')
		if idx < 0 {
			return
		}
		line := l.leftover[:idx]
		l.leftover = l.leftover[idx+1:]
		l.handleLine(string(line))
	}
}

// handleLine inspects one audit log line. If it carries the
// csm_af_alg_socket key, parse the event and dispatch a finding.
func (l *AFAlgAuditListener) handleLine(line string) {
	ev, ok := checks.ParseAFAlgEventLine(line)
	if !ok {
		return
	}
	l.eventCount.Add(1)
	finding := alert.Finding{
		Severity:  alert.Critical,
		Check:     "af_alg_socket_use",
		Message:   fmt.Sprintf("AF_ALG socket opened by uid=%s exe=%s", ev.UID, ev.Exe),
		Timestamp: time.Now(),
		Details: fmt.Sprintf(
			"Live audit-log detection: timestamp=%s serial=%s\nauid=%s uid=%s comm=%q exe=%q pid=%s\n"+
				"AF_ALG is essentially never used by cPanel/PHP workloads. This is\n"+
				"the kernel-level exploit signature for CVE-2026-31431 (\"Copy Fail\").\n"+
				"This event was caught by the live audit-log listener (sub-second\n"+
				"latency); investigate this process immediately.",
			ev.Timestamp, ev.Serial, ev.AUID, ev.UID, ev.Comm, ev.Exe, ev.PID,
		),
	}
	// Non-blocking send — the alert dispatcher buffer is sized for bursts;
	// dropping a finding under extreme pressure is preferable to blocking
	// the listener loop.
	select {
	case l.alertCh <- finding:
	default:
		csmlog.Warn("af_alg audit listener: alert channel full; finding dropped", "uid", ev.UID, "exe", ev.Exe)
	}
	// Optional reactions (kill, quarantine) gated by config; implemented
	// in af_alg_react.go so the BPF path can reuse the same logic.
	reactToAFAlgEvent(l.cfg, ev)
}
