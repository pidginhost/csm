package daemon

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// mailIPEntry tracks failed-auth timestamps, successful-login timestamps, and
// suppression state for one IP. The success timestamps let the brute-force and
// compromise gates distinguish a busy legit client (success-dominant) from an
// attacker (failure-dominant).
type mailIPEntry struct {
	times      []time.Time
	succ       []time.Time
	suppressed time.Time
	lastSeen   time.Time
}

// successDominant reports whether this IP behaves like a legit busy client
// rather than a brute-forcer: it has successful logins in the window and at
// least as many successes as failures. A NATed office mailbox cluster with one
// stale-password device drips a few failures against thousands of successes;
// without this gate the per-IP brute threshold would auto-block the whole
// office. Caller must hold t.mu and must have pruned both slices to the current
// window first.
func (e *mailIPEntry) successDominant() bool {
	return len(e.succ) > 0 && len(e.succ) >= len(e.times)
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
	compromiseSuppressed time.Time
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

	// Diagnostic counters (guarded by mu): cumulative Record invocations and
	// findings emitted, logged periodically by the daemon to pin whether the
	// non-cPanel dovecot brute-force path sees traffic and escalates.
	recordCalls     int64
	findingsEmitted int64
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

	t.recordCalls++

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
		e.succ = pruneTimes(e.succ, cutoff)
		if !e.successDominant() {
			e.suppressed = now.Add(t.suppression)
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "mail_bruteforce",
				Message: fmt.Sprintf("Mail auth brute force from %s: %d failed auths in %v",
					ip, len(e.times), t.window),
				Details:   "Real-time detection of dovecot imap/pop3/managesieve auth failures",
				Timestamp: now,
				SourceIP:  ip,
			})
		}
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
			cidr := prefix + ".0/24"
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "mail_subnet_spray",
				Message: fmt.Sprintf("Mail password spray from %s.0/24: %d unique IPs in %v",
					prefix, len(s.ips), t.window),
				Details:   "Real-time detection of mail auth failures from many IPs in one /24",
				Timestamp: now,
				SourceIP:  cidr,
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
			_, acctDomain := alert.SplitEmail(account)
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "mail_account_spray",
				Message: fmt.Sprintf("Mail password spray targeting %s: %d unique IPs in %v",
					account, len(a.ips), t.window),
				Details:   "Distributed login attempts across many IPs against one mailbox (visibility only — no auto-block).",
				Timestamp: now,
				SourceIP:  ip,
				Domain:    acctDomain,
				Mailbox:   account,
			})
		}
	}

	t.enforceMaxTracked()
	t.findingsEmitted += int64(len(findings))
	return findings
}

// Stats returns cumulative Record invocations and findings emitted since
// startup. Used by the daemon's periodic diagnostic log.
func (t *mailAuthTracker) Stats() (calls, emits int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.recordCalls, t.findingsEmitted
}

// RecordSuccess processes a successful mail login. Emits mail_account_compromised
// when the successful IP has recent failed auths for the same account AND that
// IP is failure-dominant (it fails more than it succeeds in the window): an
// attacker that guessed the password after repeated failures. A success-dominant
// IP is a busy legit client that merely mistyped, so it is not flagged -- this
// is what stops a NATed office from auto-blocking itself.
//
// ip and account MUST both be non-empty. Caller filters infra/private/loopback
// IPs before invoking.
func (t *mailAuthTracker) RecordSuccess(ip, account string) []alert.Finding {
	if ip == "" || account == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// Successes create per-IP entries too; keep the tracker bounded on every
	// path (runs under the held lock, before Unlock).
	defer t.enforceMaxTracked()

	now := t.now()
	cutoff := now.Add(-t.window)

	// Track per-IP successes first, unconditionally, so the brute-force and
	// compromise gates see the full success history for this IP even before any
	// account is tracked.
	e, ok := t.ips[ip]
	if !ok {
		e = &mailIPEntry{}
		t.ips[ip] = e
	}
	e.succ = pruneTimes(e.succ, cutoff)
	e.succ = append(e.succ, now)
	e.lastSeen = now

	a, ok := t.accounts[account]
	if !ok {
		return nil
	}
	if _, failedRecently := a.ips[ip]; !failedRecently {
		return nil
	}
	// A success from an IP that succeeds far more than it fails is a legit owner
	// who mistyped, not a takeover. Genuine password guessing is failure-dominant.
	e.times = pruneTimes(e.times, cutoff)
	if e.successDominant() {
		return nil
	}
	if now.Before(a.compromiseSuppressed) {
		return nil
	}
	a.compromiseSuppressed = now.Add(t.suppression)
	_, compDomain := alert.SplitEmail(account)
	return []alert.Finding{{
		Severity: alert.Critical,
		Check:    "mail_account_compromised",
		Message: fmt.Sprintf("Mail account compromise: successful login for %s from %s after recent auth failures",
			account, ip),
		Details:   "Attacker succeeded after one or more failed attempts from the same IP for this mailbox. Rotate password and revoke sessions.",
		Timestamp: now,
		SourceIP:  ip,
		Domain:    compDomain,
		Mailbox:   account,
	}}
}

// Purge removes stale entries older than (window + suppression).
// Called from a background goroutine every minute.
func (t *mailAuthTracker) Purge() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	activityCutoff := now.Add(-(t.window + t.suppression))
	windowCutoff := now.Add(-t.window)

	for k, e := range t.ips {
		e.times = pruneTimes(e.times, windowCutoff)
		e.succ = pruneTimes(e.succ, windowCutoff)
		if len(e.times) == 0 && len(e.succ) == 0 && !e.lastSeen.After(activityCutoff) {
			delete(t.ips, k)
		}
	}
	for k, s := range t.subnets {
		for ip, ts := range s.ips {
			if ts.Before(windowCutoff) {
				delete(s.ips, ip)
			}
		}
		if len(s.ips) == 0 && !s.lastSeen.After(activityCutoff) {
			delete(t.subnets, k)
		}
	}
	for k, a := range t.accounts {
		for ip, ts := range a.ips {
			if ts.Before(windowCutoff) {
				delete(a.ips, ip)
			}
		}
		if len(a.ips) == 0 && !a.lastSeen.After(activityCutoff) {
			delete(t.accounts, k)
		}
	}
}

// enforceMaxTracked evicts the least-recently-seen entries until the IP count
// is <= 95% of maxTracked. Batch target avoids re-sorting on every subsequent
// insert. Caller must hold t.mu.
func (t *mailAuthTracker) enforceMaxTracked() {
	total := len(t.ips) + len(t.subnets) + len(t.accounts)
	if total <= t.maxTracked {
		return
	}

	// Evict to 95% of cap so subsequent inserts don't re-trigger the sort.
	target := t.maxTracked * 95 / 100

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

	for i := 0; i < len(victims); i++ {
		if len(t.ips)+len(t.subnets)+len(t.accounts) <= target {
			break
		}
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

// isMailAuthLine returns true for dovecot imap/pop3/managesieve login events.
func isMailAuthLine(line string) bool {
	if !strings.Contains(line, "dovecot:") {
		return false
	}
	return strings.Contains(line, "imap-login:") ||
		strings.Contains(line, "pop3-login:") ||
		strings.Contains(line, "managesieve-login:")
}

// extractMailLoginEvent parses a dovecot login line and returns
// (ip, account, success). Returns empty strings and false on parse failure.
//
// Real dovecot wire format (validated against production logs):
//
//	Success: "imap-login: Logged in: user=<alice@x.ro>, method=PLAIN, rip=..."
//	Failure: "imap-login: Login aborted: ... (auth failed, N attempts ...): user=<...>, method=..., rip=..."
//
// The success marker is "Logged in" (NOT "Login:" — an earlier version of
// this parser used the wrong marker and silently skipped every successful
// login, which in turn broke RecordSuccess-based compromise detection).
// The failure marker is "(auth failed" with the opening paren, which
// distinguishes real auth failures from Login-aborted reasons like
// "no auth attempts" or TLS handshake errors.
func extractMailLoginEvent(line string) (ip, account string, success bool) {
	switch {
	case strings.Contains(line, "-login: Logged in"):
		success = true
	case strings.Contains(line, "(auth failed"):
		success = false
	default:
		return "", "", false
	}

	// Extract account key via the configured (or default) extractor.
	account = currentAccountExtractor().Extract(line)

	// Extract rip=... field. Delimited by comma or whitespace.
	if i := strings.Index(line, "rip="); i >= 0 {
		rest := line[i+len("rip="):]
		end := strings.IndexAny(rest, ", \n")
		if end < 0 {
			end = len(rest)
		}
		ip = rest[:end]
	}

	return ip, account, success
}
