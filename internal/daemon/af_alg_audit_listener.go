//go:build linux

package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
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
	alertCh         chan<- alert.Finding
	cfg             *config.Config
	path            string
	inotifyFd       int
	file            *os.File
	pos             int64
	leftover        []byte // partial line accumulator across reads
	droppedOversize bool   // mid-drop of a line that overflowed the cap
	cursorAnchor    []byte // bytes immediately before pos, used to detect copytruncate rewrites

	// Re-open retry state. A rotation (or a broken inotify fd) sets
	// reopenPending; each tick retries open() once its backoff has elapsed,
	// so one failed re-open no longer blinds the listener forever.
	reopenPending   bool
	reopenBackoff   time.Duration
	reopenNotBefore time.Time

	eventCount atomic.Uint64 // observed by tests / metrics
}

// Re-open backoff bounds. Start small so a normal logrotate race (the
// replacement file lands a beat after the move) recovers within a tick or two,
// then grow to a cap so a genuinely absent audit log does not spin.
const (
	afAlgReopenBackoffInitial = 1 * time.Second
	afAlgReopenBackoffMax     = 30 * time.Second
)

func nextAFAlgReopenBackoff(cur time.Duration) time.Duration {
	if cur <= 0 {
		return afAlgReopenBackoffInitial
	}
	next := cur * 2
	if next > afAlgReopenBackoffMax {
		return afAlgReopenBackoffMax
	}
	return next
}

// afAlgMaxLeftoverBytes caps the partial-line accumulator. A real auditd
// SYSCALL record is well under 1 KiB; 64 KiB leaves generous headroom while
// bounding memory if a record never terminates.
const afAlgMaxLeftoverBytes = 64 * 1024

// afAlgCursorAnchorBytes is the suffix length remembered at the current read
// cursor. On each tail tick the listener verifies those bytes still sit before
// pos; if copytruncate rewrote the file past the old cursor between ticks, the
// anchor no longer matches and the listener resets to offset 0 instead of
// skipping the fresh records.
const afAlgCursorAnchorBytes = 64

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
	l.droppedOversize = false
	l.refreshCursorAnchor()
	l.reopenPending = false
	l.reopenBackoff = 0
	l.reopenNotBefore = time.Time{}
	return nil
}

// reopenIfDue services a pending re-open. It returns true when the listener is
// ready to tail this tick: either no re-open was pending, or a due re-open
// succeeded. On a failed re-open it keeps reopenPending set and schedules the
// next attempt with exponential backoff, returning false so the caller skips
// tailing a file that is not yet in place. A re-open still gated by its backoff
// window also returns false without touching the filesystem.
func (l *AFAlgAuditListener) reopenIfDue(now time.Time) bool {
	if !l.reopenPending {
		return true
	}
	if now.Before(l.reopenNotBefore) {
		return false
	}
	if err := l.open(); err != nil {
		l.reopenBackoff = nextAFAlgReopenBackoff(l.reopenBackoff)
		l.reopenNotBefore = now.Add(l.reopenBackoff)
		csmlog.Warn("af_alg audit listener: re-open failed; will retry",
			"err", err, "retry_in", l.reopenBackoff)
		return false
	}
	return true
}

// Run drains inotify events and tails the audit log until ctx is done.
// Polls the inotify fd every poll interval (matches forwarder_watcher's
// approach — no epoll, easier to reason about).
//
// On rotation (IN_MOVE_SELF / IN_DELETE_SELF) the listener re-opens the
// new audit.log and continues from its end. If the replacement file is not
// on disk yet the re-open is retried with backoff on subsequent ticks
// instead of giving up (one failed re-open used to blind the listener until
// the next successful rotation). A broken inotify fd is recovered the same
// way. There is still a brief window during rotation where events written
// between the move and the re-open can be missed; the periodic critical-tier
// check covers that gap via its persistent cursor.
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
	// 500 ms tick gives sub-second average detection latency. The cost
	// is ~2 cheap syscalls/sec (inotify Read returns EAGAIN immediately
	// when nothing's queued, file Seek+Read returns EOF cheaply when
	// no new bytes). Cheap enough to not bother with epoll/select for
	// a v1 — we can refactor to true event-driven if we ever need
	// hundred-microsecond latency.
	ticker := time.NewTicker(500 * time.Millisecond)
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
			// A rotation needs a re-open; a broken inotify fd (ok=false) needs
			// one too, so a persistently unhealthy watch is rebuilt instead of
			// leaving us blind. This is the "safety net" the retry loop provides.
			if rotated || !ok {
				l.reopenPending = true
			}
			if !l.reopenIfDue(time.Now()) {
				continue
			}
			l.tail(readBuf)
		}
	}
}

// drainInotify reads any queued inotify events. Returns:
//
//	ok=false  on read errors that aren't EAGAIN/EINTR (the listener
//	          should skip this tick entirely; the next tick re-tries).
//	rotated=true if any IN_MOVE_SELF or IN_DELETE_SELF event was seen.
//
// IN_MODIFY events implicitly trigger a tail() in the caller because we
// always read at the end of each tick on success.
func (l *AFAlgAuditListener) drainInotify(buf []byte) (rotated, ok bool) {
	for {
		n, err := unix.Read(l.inotifyFd, buf)
		if err != nil {
			// EAGAIN: no more events queued — the normal terminator.
			// EINTR: interrupted by signal, also benign — retry next tick.
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				return rotated, true
			}
			// Anything else (EBADF after a stray Close, EIO, EFAULT)
			// signals the inotify fd is no longer healthy. Surface it so
			// the operator notices, and return ok=false: the caller marks a
			// re-open pending and the backoff retry rebuilds the watch.
			csmlog.Warn("af_alg audit listener: inotify read error", "err", err)
			return rotated, false
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
	for {
		// Detect in-place truncation (copytruncate logrotate, or a manual
		// truncate). When the file shrinks below our read cursor, seeking
		// forward would skip the content rewritten from offset 0 and the
		// listener would go blind. Size alone misses a fast truncate+rewrite
		// that grows past the old cursor before this tick, so verify the
		// cursor anchor too.
		if fi, err := l.file.Stat(); err == nil {
			switch {
			case fi.Size() < l.pos:
				l.resetTailCursor()
			case l.cursorAnchorChanged():
				l.resetTailCursor()
			}
		}

		verifiedPos := l.pos
		verifiedAnchor := append([]byte(nil), l.cursorAnchor...)
		if _, err := l.file.Seek(l.pos, 0); err != nil {
			csmlog.Warn("af_alg audit listener: seek failed", "err", err)
			return
		}
		for {
			n, err := l.file.Read(buf)
			if n > 0 {
				if l.cursorAnchorChangedAt(verifiedPos, verifiedAnchor) {
					l.resetTailCursor()
					break
				}
				l.feed(buf[:n])
				l.pos += int64(n)
			}
			if err != nil {
				if l.cursorAnchorChangedAt(verifiedPos, verifiedAnchor) {
					l.resetTailCursor()
					break
				}
				// io.EOF or EAGAIN: out of data for this tick.
				l.refreshCursorAnchor()
				return
			}
		}
	}
}

func (l *AFAlgAuditListener) resetTailCursor() {
	l.pos = 0
	l.leftover = nil
	l.droppedOversize = false
	l.cursorAnchor = nil
}

func (l *AFAlgAuditListener) cursorAnchorChanged() bool {
	return l.cursorAnchorChangedAt(l.pos, l.cursorAnchor)
}

func (l *AFAlgAuditListener) cursorAnchorChangedAt(pos int64, anchor []byte) bool {
	if l.file == nil || pos <= 0 || len(anchor) == 0 {
		return false
	}
	if int64(len(anchor)) > pos {
		return true
	}
	buf := make([]byte, len(anchor))
	n, err := l.file.ReadAt(buf, pos-int64(len(buf)))
	if err != nil || n != len(buf) {
		return true
	}
	return !bytes.Equal(buf, anchor)
}

func (l *AFAlgAuditListener) refreshCursorAnchor() {
	if l.file == nil || l.pos <= 0 {
		l.cursorAnchor = nil
		return
	}
	n := afAlgCursorAnchorBytes
	if l.pos < int64(n) {
		n = int(l.pos)
	}
	buf := make([]byte, n)
	read, err := l.file.ReadAt(buf, l.pos-int64(n))
	if err != nil || read != n {
		l.cursorAnchor = nil
		return
	}
	l.cursorAnchor = buf
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
			// No complete line yet. A real audit record fits well under the
			// cap; an unterminated buffer past it is garbage (truncated write,
			// binary noise, or an attacker-stretched exe= path). Drop it so the
			// accumulator cannot grow without bound, and resync at the next
			// newline.
			if len(l.leftover) > afAlgMaxLeftoverBytes {
				l.leftover = nil
				l.droppedOversize = true
			}
			return
		}
		line := l.leftover[:idx]
		l.leftover = l.leftover[idx+1:]
		// Skip the remainder of a line whose head was already dropped for
		// exceeding the cap: it is a partial record, not a parseable line.
		if l.droppedOversize {
			l.droppedOversize = false
			continue
		}
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
