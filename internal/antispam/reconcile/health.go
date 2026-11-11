package reconcile

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
)

// Consecutive probe results that change rspamd's state.
const (
	pingDown = 3
	pingUp   = 2
)

// Health tracks rspamd's scan socket and the scans the mail logs record
// while antispam is enabled. The probe loop and the log
// watchers use it concurrently.
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
	// stack and milterAction word the scan error finding.
	stack        antispam.MailStack
	milterAction string
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

// SetStack words failed scans for the host's mail stack: on Postfix by
// what milterAction, postfix's milter_default_action, does with mail while
// rspamd's milter fails.
func (h *Health) SetStack(stack antispam.MailStack, milterAction string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stack, h.milterAction = stack, milterAction
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

// Line records one Exim main-log line: a scan marker Exim wrote counts as
// Scan counts it, any other line not at all.
func (h *Health) Line(line string, now time.Time) (findings []alert.Finding, recovered bool) {
	s, marker := antispam.ParseScan(line)
	if !marker {
		return nil, false
	}
	return h.Scan(s, now)
}

// Scan records one scan and returns the finding to report when scans start
// failing, and whether a successful scan cleared a failure.
func (h *Health) Scan(s antispam.Scan, now time.Time) (findings []alert.Finding, recovered bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case !h.enabled:
		return nil, false
	case s.OK:
		recovered = h.scanErrors > 0
		h.scanErrors = 0
		return nil, recovered
	}
	h.scanErrors++
	h.lastErr = now
	if h.scanErrors > 1 {
		return nil, false
	}
	h.firstErr = now
	return []alert.Finding{scanErrorFinding(1, now, now, h.stack, h.milterAction)}, false
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
		out = append(out, scanErrorFinding(h.scanErrors, h.firstErr, h.lastErr, h.stack, h.milterAction))
	}
	return out
}
