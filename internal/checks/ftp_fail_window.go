package checks

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// FTPFailThreshold is how many failures in the window make an FTP brute force.
const FTPFailThreshold = ftpFailThreshold

// ftpLoginsFromJournal is set once the daemon reads pure-ftpd's journal entries.
var ftpLoginsFromJournal atomic.Bool

// SetFTPLoginsFromJournal records whether the daemon reads FTP logins from
// pure-ftpd's journal entries.
func SetFTPLoginsFromJournal(on bool) { ftpLoginsFromJournal.Store(on) }

// FTPFailWindow counts pure-ftpd authentication failures per address over the
// FTP failure window as a live reader sees them. An address is reported when
// it reaches the threshold and then once per window while the burst lasts,
// so a long burst does not block again an address the operator unblocked.
type FTPFailWindow struct {
	mu       sync.Mutex
	t        *ftpFailTracker
	reported map[string]time.Time
}

// NewFTPFailWindow returns an empty window.
func NewFTPFailWindow() *FTPFailWindow {
	return &FTPFailWindow{t: newFTPFailTracker(), reported: map[string]time.Time{}}
}

// Failure records a failure from ip at at, received at now. It returns the
// failures in the window, the window in minutes, and whether to report.
func (w *FTPFailWindow) Failure(ip string, at, now time.Time, cfg *config.Config) (count, windowMin int, report bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	windowMin = effectiveFTPFailWindowMin(cfg)
	window := time.Duration(windowMin) * time.Minute
	w.t.evict(now, windowMin)
	for addr, when := range w.reported {
		if now.Sub(when) >= window {
			delete(w.reported, addr)
		}
	}
	if at.After(now) {
		at = now
	}
	if at.Before(now.Add(-window)) {
		return w.t.count(ip), windowMin, false
	}
	// Bound history by age, not source count: strong old candidates must
	// never prevent a new address from accumulating its failures.
	w.t.record(ip, at)
	count = w.t.count(ip)
	if count < ftpFailThreshold {
		return count, windowMin, false
	}
	// Reports expire with the window, which bounds them; a cap here would let
	// a large enough burst stop every later report.
	if _, done := w.reported[ip]; done {
		return count, windowMin, false
	}
	w.reported[ip] = now
	return count, windowMin, true
}

// LoginFinding keeps the live reader's brute-force history in the same login
// finding the scheduled scan emits. Reading a login does not add a failure.
func (w *FTPFailWindow) LoginFinding(line string, at time.Time, cfg *config.Config) (alert.Finding, bool) {
	f, ok := FTPLoginFinding(line, cfg)
	if !ok {
		return f, false
	}
	w.mu.Lock()
	w.t.evict(at, effectiveFTPFailWindowMin(cfg))
	n := w.t.count(f.SourceIP)
	w.mu.Unlock()
	if n >= ftpFailThreshold {
		_, account := ftpLoginFields(line)
		f = ftpLoginFinding(f.SourceIP, account, line, n)
	}
	return f, true
}
