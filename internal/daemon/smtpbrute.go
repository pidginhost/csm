package daemon

import (
	"fmt"
	"sort"
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

// Record processes one dovecot auth-failure observation. Returns zero or more
// findings that callers should append to their finding slice.
//
// ip MUST be non-private, non-loopback, and non-infra — callers enforce this
// before invoking Record.
func (t *smtpAuthTracker) Record(ip, account string) []alert.Finding {
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
		e = &smtpIPEntry{}
		t.ips[ip] = e
	}
	e.times = pruneTimes(e.times, cutoff)
	e.times = append(e.times, now)
	e.lastSeen = now

	if len(e.times) >= t.perIPThreshold && !now.Before(e.suppressed) {
		e.suppressed = now.Add(t.suppression)
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "smtp_bruteforce",
			Message: fmt.Sprintf("SMTP brute force from %s: %d failed auths in %v",
				ip, len(e.times), t.window),
			Details:   "Real-time detection of dovecot_login auth failures",
			Timestamp: now,
		})
	}

	// --- Per-/24 subnet tracker (IPv4 only) ---
	if prefix := extractPrefix24Daemon(ip); prefix != "" {
		s, ok := t.subnets[prefix]
		if !ok {
			s = &smtpSubnetEntry{ips: make(map[string]time.Time)}
			t.subnets[prefix] = s
		}
		pruneSubnetIPs(s, cutoff)
		s.ips[ip] = now
		s.lastSeen = now

		if len(s.ips) >= t.subnetThreshold && !now.Before(s.suppressed) {
			s.suppressed = now.Add(t.suppression)
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "smtp_subnet_spray",
				Message: fmt.Sprintf("SMTP password spray from %s.0/24: %d unique IPs in %v",
					prefix, len(s.ips), t.window),
				Details:   "Real-time detection of dovecot_login auth failures from many IPs in one /24",
				Timestamp: now,
			})
		}
	}

	// --- Per-account spray tracker ---
	if account != "" {
		a, ok := t.accounts[account]
		if !ok {
			a = &smtpAccountEntry{ips: make(map[string]time.Time)}
			t.accounts[account] = a
		}
		pruneAccountIPs(a, cutoff)
		a.ips[ip] = now
		a.lastSeen = now

		if len(a.ips) >= t.accountSprayThreshold && !now.Before(a.suppressed) {
			a.suppressed = now.Add(t.suppression)
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "smtp_account_spray",
				Message: fmt.Sprintf("SMTP password spray targeting %s: %d unique IPs in %v",
					account, len(a.ips), t.window),
				Details:   "Distributed login attempts across many IPs against one mailbox (visibility only — no auto-block).",
				Timestamp: now,
			})
		}
	}

	t.enforceMaxTracked()
	return findings
}

// pruneTimes drops timestamps older than cutoff. Reuses the backing array.
func pruneTimes(times []time.Time, cutoff time.Time) []time.Time {
	recent := times[:0]
	for _, ts := range times {
		if !ts.Before(cutoff) {
			recent = append(recent, ts)
		}
	}
	return recent
}

// extractPrefix24Daemon returns the first three octets of an IPv4 address as
// "a.b.c", or "" if the input isn't an IPv4 address in dotted-quad form.
func extractPrefix24Daemon(ip string) string {
	parts := 0
	end := 0
	for i := 0; i < len(ip); i++ {
		if ip[i] == '.' {
			parts++
			if parts == 3 {
				end = i
				break
			}
		}
	}
	if parts != 3 {
		return ""
	}
	// Reject IPv6 mapped or containing colons.
	for i := 0; i < end; i++ {
		if ip[i] == ':' {
			return ""
		}
	}
	return ip[:end]
}

// pruneSubnetIPs drops per-/24 IP entries whose last-seen is older than cutoff.
func pruneSubnetIPs(s *smtpSubnetEntry, cutoff time.Time) {
	for ip, ts := range s.ips {
		if ts.Before(cutoff) {
			delete(s.ips, ip)
		}
	}
}

// pruneAccountIPs drops per-account IP entries whose last-seen is older than cutoff.
func pruneAccountIPs(a *smtpAccountEntry, cutoff time.Time) {
	for ip, ts := range a.ips {
		if ts.Before(cutoff) {
			delete(a.ips, ip)
		}
	}
}

// Purge removes entries with no recent activity (older than window + suppression).
// Called from a background goroutine every minute.
func (t *smtpAuthTracker) Purge() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	activityCutoff := now.Add(-(t.window + t.suppression))

	for k, e := range t.ips {
		e.times = pruneTimes(e.times, now.Add(-t.window))
		if len(e.times) == 0 && !e.lastSeen.After(activityCutoff) {
			delete(t.ips, k)
		}
	}
	for k, s := range t.subnets {
		pruneSubnetIPs(s, now.Add(-t.window))
		if len(s.ips) == 0 && !s.lastSeen.After(activityCutoff) {
			delete(t.subnets, k)
		}
	}
	for k, a := range t.accounts {
		pruneAccountIPs(a, now.Add(-t.window))
		if len(a.ips) == 0 && !a.lastSeen.After(activityCutoff) {
			delete(t.accounts, k)
		}
	}
}

// enforceMaxTracked evicts the least-recently-seen entries until the total
// number of tracked entities (IPs + subnets + accounts) is <= maxTracked.
// Caller must hold t.mu.
func (t *smtpAuthTracker) enforceMaxTracked() {
	total := len(t.ips) + len(t.subnets) + len(t.accounts)
	if total <= t.maxTracked {
		return
	}

	type victim struct {
		kind string // "ip" | "subnet" | "account"
		key  string
		seen time.Time
	}
	victims := make([]victim, 0, total)
	for k, v := range t.ips {
		victims = append(victims, victim{"ip", k, v.lastSeen})
	}
	for k, v := range t.subnets {
		victims = append(victims, victim{"subnet", k, v.lastSeen})
	}
	for k, v := range t.accounts {
		victims = append(victims, victim{"account", k, v.lastSeen})
	}
	sort.Slice(victims, func(i, j int) bool { return victims[i].seen.Before(victims[j].seen) })

	over := total - t.maxTracked
	for i := 0; i < over && i < len(victims); i++ {
		v := victims[i]
		switch v.kind {
		case "ip":
			delete(t.ips, v.key)
		case "subnet":
			delete(t.subnets, v.key)
		case "account":
			delete(t.accounts, v.key)
		}
	}
}
