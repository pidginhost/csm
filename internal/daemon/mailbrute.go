package daemon

import (
	"fmt"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// mailIPEntry tracks failed-auth timestamps and suppression state for one IP.
type mailIPEntry struct {
	times      []time.Time
	suppressed time.Time
	lastSeen   time.Time
}

// mailSubnetEntry tracks unique attacker IPs within a /24.
type mailSubnetEntry struct {
	ips        map[string]time.Time
	suppressed time.Time
	lastSeen   time.Time
}

// mailAccountEntry tracks unique attacker IPs per mailbox, plus a separate
// suppression clock for compromise findings emitted by RecordSuccess.
type mailAccountEntry struct {
	ips                  map[string]time.Time
	suppressed           time.Time
	compromiseSuppressed time.Time //nolint:unused
	lastSeen             time.Time
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

// Record processes one dovecot IMAP/POP3/ManageSieve auth-failure observation.
// Returns zero or more findings that callers should append.
//
// ip MUST be non-private, non-loopback, and non-infra — callers enforce this
// before invoking Record.
func (t *mailAuthTracker) Record(ip, account string) []alert.Finding {
	if ip == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	cutoff := now.Add(-t.window)
	var findings []alert.Finding

	// --- Per-IP tracker ---
	e, ok := t.ips[ip]
	if !ok {
		e = &mailIPEntry{}
		t.ips[ip] = e
	}
	e.times = pruneTimes(e.times, cutoff)
	e.times = append(e.times, now)
	e.lastSeen = now

	if len(e.times) >= t.perIPThreshold && !now.Before(e.suppressed) {
		e.suppressed = now.Add(t.suppression)
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "mail_bruteforce",
			Message: fmt.Sprintf("Mail auth brute force from %s: %d failed auths in %v",
				ip, len(e.times), t.window),
			Details:   "Real-time detection of dovecot imap/pop3/managesieve auth failures",
			Timestamp: now,
		})
	}

	// --- Per-/24 subnet tracker (IPv4 only) ---
	if prefix := extractPrefix24Daemon(ip); prefix != "" {
		s, ok := t.subnets[prefix]
		if !ok {
			s = &mailSubnetEntry{ips: make(map[string]time.Time)}
			t.subnets[prefix] = s
		}
		for ipKey, ts := range s.ips {
			if ts.Before(cutoff) {
				delete(s.ips, ipKey)
			}
		}
		s.ips[ip] = now
		s.lastSeen = now

		if len(s.ips) >= t.subnetThreshold && !now.Before(s.suppressed) {
			s.suppressed = now.Add(t.suppression)
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "mail_subnet_spray",
				Message: fmt.Sprintf("Mail password spray from %s.0/24: %d unique IPs in %v",
					prefix, len(s.ips), t.window),
				Details:   "Real-time detection of mail auth failures from many IPs in one /24",
				Timestamp: now,
			})
		}
	}

	// --- Per-account spray tracker ---
	if account != "" {
		a, ok := t.accounts[account]
		if !ok {
			a = &mailAccountEntry{ips: make(map[string]time.Time)}
			t.accounts[account] = a
		}
		for ipKey, ts := range a.ips {
			if ts.Before(cutoff) {
				delete(a.ips, ipKey)
			}
		}
		a.ips[ip] = now
		a.lastSeen = now

		if len(a.ips) >= t.accountSprayThreshold && !now.Before(a.suppressed) {
			a.suppressed = now.Add(t.suppression)
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "mail_account_spray",
				Message: fmt.Sprintf("Mail password spray targeting %s: %d unique IPs in %v",
					account, len(a.ips), t.window),
				Details:   "Distributed login attempts across many IPs against one mailbox (visibility only — no auto-block).",
				Timestamp: now,
			})
		}
	}

	return findings
}

// RecordSuccess processes a successful mail login. Implemented in Mail Task 4.
func (t *mailAuthTracker) RecordSuccess(ip, account string) []alert.Finding {
	return nil
}

// Purge removes stale entries. Implemented in Mail Task 5.
func (t *mailAuthTracker) Purge() {}
