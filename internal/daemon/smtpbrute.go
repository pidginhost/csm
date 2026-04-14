package daemon

import (
	"fmt"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// smtpIPEntry tracks failed-auth timestamps and suppression state for one IP.
type smtpIPEntry struct {
	times      []time.Time
	suppressed time.Time
	lastSeen   time.Time
}

// smtpSubnetEntry tracks unique attacker IPs within a /24.
type smtpSubnetEntry struct {
	ips        map[string]time.Time // ip -> firstSeen in window
	suppressed time.Time
	lastSeen   time.Time
}

// smtpAccountEntry tracks unique attacker IPs per mailbox.
type smtpAccountEntry struct {
	ips        map[string]time.Time
	suppressed time.Time
	lastSeen   time.Time
}

// smtpAuthTracker aggregates dovecot auth-failure events into three
// detection signals: per-IP brute force, per-/24 password spray, and
// per-mailbox account spray.
//
// Thread-safe; Record may be called concurrently from multiple log readers.
type smtpAuthTracker struct {
	mu sync.Mutex

	perIPThreshold        int
	subnetThreshold       int
	accountSprayThreshold int
	window                time.Duration
	suppression           time.Duration
	maxTracked            int
	now                   func() time.Time

	ips      map[string]*smtpIPEntry
	subnets  map[string]*smtpSubnetEntry
	accounts map[string]*smtpAccountEntry
}

// newSMTPAuthTracker constructs a tracker. `now` is injected so tests can
// use deterministic clocks; pass `time.Now` in production.
func newSMTPAuthTracker(
	perIPThreshold int,
	subnetThreshold int,
	accountSprayThreshold int,
	window time.Duration,
	suppression time.Duration,
	maxTracked int,
	now func() time.Time,
) *smtpAuthTracker {
	if now == nil {
		now = time.Now
	}
	return &smtpAuthTracker{
		perIPThreshold:        perIPThreshold,
		subnetThreshold:       subnetThreshold,
		accountSprayThreshold: accountSprayThreshold,
		window:                window,
		suppression:           suppression,
		maxTracked:            maxTracked,
		now:                   now,
		ips:                   make(map[string]*smtpIPEntry),
		subnets:               make(map[string]*smtpSubnetEntry),
		accounts:              make(map[string]*smtpAccountEntry),
	}
}

// Size returns the total number of tracked entities (IPs + subnets + accounts).
func (t *smtpAuthTracker) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.ips) + len(t.subnets) + len(t.accounts)
}

// Record is implemented in the next task. Stub is here so other call sites
// can compile while TDD progresses.
func (t *smtpAuthTracker) Record(ip, account string) []alert.Finding {
	_ = fmt.Sprintf // silence unused import warnings until Record is filled in
	return nil
}

// Purge is implemented later.
func (t *smtpAuthTracker) Purge() {}
