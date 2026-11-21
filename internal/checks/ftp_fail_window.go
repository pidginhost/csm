package checks

import (
	"sync"
	"sync/atomic"
	"time"

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

// Failure records a failure from ip at at. It returns the address's failures
// in the window, the window in minutes, and whether to report a brute force.
func (w *FTPFailWindow) Failure(ip string, at time.Time, cfg *config.Config) (count, windowMin int, report bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	windowMin = effectiveFTPFailWindowMin(cfg)
	window := time.Duration(windowMin) * time.Minute
	w.t.evict(at, windowMin)
	w.t.record(ip, at)
	w.t.capIPs(maxTrackedIPs)
	for addr, when := range w.reported {
		if at.Sub(when) >= window {
			delete(w.reported, addr)
		}
	}
	count = w.t.count(ip)
	if count < ftpFailThreshold {
		return count, windowMin, false
	}
	// Reports expire with the window, which bounds them; a cap here would let
	// a large enough burst stop every later report.
	if _, done := w.reported[ip]; done {
		return count, windowMin, false
	}
	w.reported[ip] = at
	return count, windowMin, true
}
