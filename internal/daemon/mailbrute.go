package daemon

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// mailIPEntry tracks failed-auth timestamps and suppression state for one IP.
type mailIPEntry struct {
	times      []time.Time //nolint:unused
	suppressed time.Time   //nolint:unused
	lastSeen   time.Time   //nolint:unused
}

// mailSubnetEntry tracks unique attacker IPs within a /24.
type mailSubnetEntry struct {
	ips        map[string]time.Time //nolint:unused
	suppressed time.Time            //nolint:unused
	lastSeen   time.Time            //nolint:unused
}

// mailAccountEntry tracks unique attacker IPs per mailbox, plus a separate
// suppression clock for compromise findings emitted by RecordSuccess.
type mailAccountEntry struct {
	ips                  map[string]time.Time //nolint:unused
	suppressed           time.Time            //nolint:unused
	compromiseSuppressed time.Time            //nolint:unused
	lastSeen             time.Time            //nolint:unused
}

// mailAuthTracker aggregates dovecot IMAP/POP3/ManageSieve auth events into
// four detection signals: per-IP brute force, per-/24 password spray,
// per-mailbox account spray, and per-account compromise (success after
// recent failures).
//
// Thread-safe; Record/RecordSuccess may be called concurrently from multiple
// log readers.
type mailAuthTracker struct {
	mu sync.Mutex

	perIPThreshold        int
	subnetThreshold       int
	accountSprayThreshold int
	window                time.Duration
	suppression           time.Duration
	maxTracked            int
	now                   func() time.Time

	ips      map[string]*mailIPEntry
	subnets  map[string]*mailSubnetEntry
	accounts map[string]*mailAccountEntry
}

// newMailAuthTracker constructs a tracker. `now` is injected so tests can
// use deterministic clocks; pass `time.Now` in production.
func newMailAuthTracker(
	perIPThreshold int,
	subnetThreshold int,
	accountSprayThreshold int,
	window time.Duration,
	suppression time.Duration,
	maxTracked int,
	now func() time.Time,
) *mailAuthTracker {
	if now == nil {
		now = time.Now
	}
	return &mailAuthTracker{
		perIPThreshold:        perIPThreshold,
		subnetThreshold:       subnetThreshold,
		accountSprayThreshold: accountSprayThreshold,
		window:                window,
		suppression:           suppression,
		maxTracked:            maxTracked,
		now:                   now,
		ips:                   make(map[string]*mailIPEntry),
		subnets:               make(map[string]*mailSubnetEntry),
		accounts:              make(map[string]*mailAccountEntry),
	}
}

// Size returns the total number of tracked entities (IPs + subnets + accounts).
func (t *mailAuthTracker) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.ips) + len(t.subnets) + len(t.accounts)
}

// Record processes a failed mail auth observation. Implemented in Mail Task 3.
func (t *mailAuthTracker) Record(ip, account string) []alert.Finding {
	_ = fmt.Sprintf // keep fmt import alive until Record body is filled in
	_ = sort.Slice  // keep sort import alive until enforceMaxTracked body is filled in
	return nil
}

// RecordSuccess processes a successful mail login. Implemented in Mail Task 4.
func (t *mailAuthTracker) RecordSuccess(ip, account string) []alert.Finding {
	return nil
}

// Purge removes stale entries. Implemented in Mail Task 5.
func (t *mailAuthTracker) Purge() {}
