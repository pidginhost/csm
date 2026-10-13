package reconcile

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
)

// Consecutive probe results that change rspamd's state (spec section 7).
const (
	pingDown = 3
	pingUp   = 2
)

// Health tracks rspamd's scan socket and Exim's scan markers while antispam
// is enabled (spec section 7). The probe loop and the Exim log watcher use
// it concurrently.
type Health struct {
	mu      sync.Mutex
	enabled bool
	socket  string
	// fails and oks count consecutive probe results; down is an outage
	// already reported, since downSince.
	fails, oks int
	down       bool
	downSince  time.Time
	// scanErrors counts failed scans since the last successful one.
	scanErrors        int
	firstErr, lastErr time.Time
}

// SetEnabled starts or stops tracking. Stopping forgets every count and
// active finding without a recovery notice; a new socket forgets the
// probe state of the old one.
func (h *Health) SetEnabled(enabled bool, socket string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !enabled {
		h.scanErrors = 0
	}
	if !enabled || socket != h.socket {
		h.fails, h.oks, h.down = 0, 0, false
	}
	h.enabled, h.socket = enabled, socket
}

// Ping records one /ping result for socket and returns the finding to
// report: rspamd down after pingDown failures in a row, once per outage, and
// recovered after pingUp successes in a row. A result for a socket no
// longer tracked, from a probe that outlived a reload, is ignored.
func (h *Health) Ping(socket string, err error, now time.Time) []alert.Finding {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.enabled || socket != h.socket {
		return nil
	}
	if err != nil {
		h.oks = 0
		h.fails++
		if h.fails >= pingDown && !h.down {
			h.down, h.downSince = true, now
			return []alert.Finding{rspamdDownFinding(h.socket, now)}
		}
		return nil
	}
	h.fails = 0
	h.oks++
	if h.down && h.oks >= pingUp {
		h.down = false
		return []alert.Finding{rspamdRecoveredFinding(h.socket, now)}
	}
	return nil
}

// Line records one Exim main-log line and returns the finding to report
// when scans start failing. A successful scan clears the failure; only a
// scan marker Exim wrote counts.
func (h *Health) Line(line string, now time.Time) []alert.Finding {
	marker, ok := antispam.ScanMarker(line)
	if !marker {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case !h.enabled:
		return nil
	case ok:
		h.scanErrors = 0
		return nil
	}
	h.scanErrors++
	h.lastErr = now
	if h.scanErrors > 1 {
		return nil
	}
	h.firstErr = now
	return []alert.Finding{scanErrorFinding(1, now, now)}
}

// Active returns the health conditions true now.
func (h *Health) Active() []alert.Finding {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []alert.Finding
	if h.down {
		out = append(out, rspamdDownFinding(h.socket, h.downSince))
	}
	if h.scanErrors > 0 {
		out = append(out, scanErrorFinding(h.scanErrors, h.firstErr, h.lastErr))
	}
	return out
}
