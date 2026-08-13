package daemon

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// smtpIPEntry tracks failed-auth timestamps and suppression state for one IP.
// slowTimes/slowAccounts hold the long-horizon failure history that catches
// attackers pacing below the fast window; slowAccounts maps each targeted
// mailbox to its most recent failure so distinct-target counting can prune.
type smtpIPEntry struct {
	times        []time.Time
	slowTimes    []time.Time
	slowAccounts map[string]time.Time
	// slowLastSuccess is the most recent successful SMTP auth from this IP.
	// A success inside the slow window marks the source as a live legitimate
	// client (e.g. an office NAT where some devices still authenticate) and
	// disqualifies the slow block.
	slowLastSuccess time.Time
	suppressed      time.Time
	lastSeen        time.Time
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

// slowBruteMinAccounts is how many distinct mailboxes a single IP's
// long-horizon failures must target before the slow-brute signal fires. A
// misconfigured client with a stale saved password hammers one mailbox; a
// mailbox walk touches several.
const slowBruteMinAccounts = config.SlowBruteMinThreshold

// Slow-brute state is nested inside a tracked IP, so maxTracked cannot bound
// it. These caps match the largest accepted threshold and keep a high-rate
// source or a stream of unique attacker-controlled mailbox names bounded.
const (
	slowBruteMaxTimesPerIP    = config.SlowBruteMaxThreshold
	slowBruteMaxAccountsPerIP = config.SlowBruteMaxThreshold
)

// slowBruteWalkAccounts fires the slow signal on distinct-mailbox breadth
// alone. A walk probing one or two passwords per mailbox stays under any
// failure-count floor forever (observed live: 34 failures across 26
// mailboxes), but no legitimate client fails against this many distinct
// mailboxes from one address without a single success.
const slowBruteWalkAccounts = 10

// pruneSlowAccounts drops per-mailbox last-failure records older than cutoff.
func pruneSlowAccounts(accounts map[string]time.Time, cutoff time.Time) {
	for acct, ts := range accounts {
		if ts.Before(cutoff) {
			delete(accounts, acct)
		}
	}
}

// appendSlowFailure retains the newest bounded history. Validation caps the
// configured threshold at the same value, so a reachable threshold is never
// discarded. Reslicing avoids copying the full history on every event.
func appendSlowFailure(times []time.Time, ts time.Time) []time.Time {
	times = append(times, ts)
	if len(times) > slowBruteMaxTimesPerIP {
		times = times[len(times)-slowBruteMaxTimesPerIP:]
	}
	return times
}

// recordSlowAccount prunes before insertion and refuses new keys after the
// per-IP cap. Three distinct live keys are sufficient for detection, so a
// capped map preserves the signal while preventing unique-name memory growth.
// The bool reports whether this event's account is represented in the map.
func recordSlowAccount(accounts map[string]time.Time, account string, now, cutoff time.Time) (map[string]time.Time, bool) {
	pruneSlowAccounts(accounts, cutoff)
	if account == "" {
		return accounts, false
	}
	if accounts == nil {
		accounts = make(map[string]time.Time)
	}
	if _, exists := accounts[account]; exists || len(accounts) < slowBruteMaxAccountsPerIP {
		accounts[account] = now
		return accounts, true
	}
	return accounts, false
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
	slowThreshold         int
	slowWindow            time.Duration
	maxTracked            int
	now                   func() time.Time

	ips      map[string]*smtpIPEntry
	subnets  map[string]*smtpSubnetEntry
	accounts map[string]*smtpAccountEntry

	// Diagnostic counters (guarded by mu): cumulative Record invocations and
	// findings emitted. The daemon logs these so a "zero smtp_bruteforce in
	// production despite thousands of auth failures" can be pinned to either
	// "Record never called" or "called but never crosses threshold".
	recordCalls     int64
	findingsEmitted int64

	// backendDownFn, when set, reports whether the active socket probe currently
	// sees the mail auth backend down. SMTP-AUTH (exim->dovecot) fails the same
	// way during a cpdoveauthd outage, so suppress brute/subnet auto-block then.
	backendDownFn func() bool
}

// SetBackendDownCheck installs the active-probe callback the tracker consults to
// learn whether the mail auth backend is down. When it returns true, brute-force
// and subnet auto-block are suppressed. Set once at startup before log readers
// begin.
func (t *smtpAuthTracker) SetBackendDownCheck(fn func() bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.backendDownFn = fn
}

// newSMTPAuthTracker constructs a tracker. `now` is injected so tests can
// use deterministic clocks; pass `time.Now` in production.
func newSMTPAuthTracker(
	perIPThreshold int,
	subnetThreshold int,
	accountSprayThreshold int,
	window time.Duration,
	suppression time.Duration,
	slowThreshold int,
	slowWindow time.Duration,
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
		slowThreshold:         slowThreshold,
		slowWindow:            slowWindow,
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

	t.recordCalls++

	now := t.now()
	cutoff := now.Add(-t.window)

	var findings []alert.Finding

	// During a mail-auth-backend outage exim->dovecot SMTP AUTH fails for every
	// user regardless of password, so the failure-rate signals would mass-block
	// legitimate senders. Suppress them while the probe reports the backend down.
	degraded := t.backendDownFn != nil && t.backendDownFn()

	// --- Per-IP tracker ---
	e, ok := t.ips[ip]
	if !ok {
		e = &smtpIPEntry{}
		t.ips[ip] = e
	}
	e.times = pruneTimes(e.times, cutoff)
	e.times = append(e.times, now)
	e.lastSeen = now

	if t.perIPThreshold > 0 && len(e.times) >= t.perIPThreshold && !now.Before(e.suppressed) && !degraded {
		e.suppressed = now.Add(t.suppression)
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "smtp_bruteforce",
			Message: fmt.Sprintf("SMTP brute force from %s: %d failed auths in %v",
				ip, len(e.times), t.window),
			Details:   "Real-time detection of dovecot_login auth failures",
			Timestamp: now,
			SourceIP:  ip,
		})
	}

	// --- Long-horizon slow-brute tracker ---
	// Catches attackers pacing below the fast window (e.g. one failure every
	// few minutes for hours). Requiring several distinct target mailboxes
	// separates a mailbox walk from a misconfigured client retrying one stale
	// saved password, which fails against a single mailbox no matter how long
	// it runs.
	if t.slowThreshold > 0 && t.slowWindow > 0 {
		if degraded {
			// Backend failures say nothing about credentials. Discard the
			// long-lived evidence so outage traffic cannot trigger a delayed
			// block as soon as the backend recovers.
			e.slowTimes = nil
			e.slowAccounts = nil
		} else {
			slowCutoff := now.Add(-t.slowWindow)
			e.slowTimes = pruneTimes(e.slowTimes, slowCutoff)
			e.slowTimes = appendSlowFailure(e.slowTimes, now)
			e.slowAccounts, _ = recordSlowAccount(e.slowAccounts, normalizeMailAuthAccount(account), now, slowCutoff)
			if e.slowLastSuccess.Before(slowCutoff) {
				e.slowLastSuccess = time.Time{}
			}
			if (len(e.slowTimes) >= t.slowThreshold || len(e.slowAccounts) >= slowBruteWalkAccounts) &&
				len(e.slowAccounts) >= slowBruteMinAccounts &&
				e.slowLastSuccess.IsZero() &&
				!now.Before(e.suppressed) {
				e.suppressed = now.Add(t.suppression)
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "smtp_bruteforce",
					Message: fmt.Sprintf("SMTP brute force from %s: %d failed auths across %d mailboxes in %v",
						ip, len(e.slowTimes), len(e.slowAccounts), t.slowWindow),
					Details:   "Long-horizon detection of paced dovecot_login auth failures that stay below the fast per-IP window",
					Timestamp: now,
					SourceIP:  ip,
				})
			}
		}
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

		if t.subnetThreshold > 0 && len(s.ips) >= t.subnetThreshold && !now.Before(s.suppressed) && !degraded {
			s.suppressed = now.Add(t.suppression)
			cidr := prefix + ".0/24"
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "smtp_subnet_spray",
				Message: fmt.Sprintf("SMTP password spray from %s.0/24: %d unique IPs in %v",
					prefix, len(s.ips), t.window),
				Details:   "Real-time detection of dovecot_login auth failures from many IPs in one /24",
				Timestamp: now,
				SourceIP:  cidr,
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

		if t.accountSprayThreshold > 0 && len(a.ips) >= t.accountSprayThreshold && !now.Before(a.suppressed) {
			a.suppressed = now.Add(t.suppression)
			_, acctDomain := alert.SplitEmail(account)
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "smtp_account_spray",
				Message: fmt.Sprintf("SMTP password spray targeting %s: %d unique IPs in %v",
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

// RecordSuccess notes a successful SMTP authentication from ip, disqualifying
// the source from the slow-brute block for as long as the success stays inside
// the slow window. Callers filter infra/private/loopback IPs first.
func (t *smtpAuthTracker) RecordSuccess(ip string) {
	if ip == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.ips[ip]
	if !ok {
		e = &smtpIPEntry{}
		t.ips[ip] = e
	}
	now := t.now()
	e.slowLastSuccess = now
	e.lastSeen = now
	t.enforceMaxTracked()
}

// Stats returns cumulative Record invocations and findings emitted since
// startup. Used by the daemon's periodic diagnostic log.
func (t *smtpAuthTracker) Stats() (calls, emits int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.recordCalls, t.findingsEmitted
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
		e.slowTimes = pruneTimes(e.slowTimes, now.Add(-t.slowWindow))
		pruneSlowAccounts(e.slowAccounts, now.Add(-t.slowWindow))
		if len(e.times) == 0 && len(e.slowTimes) == 0 && !e.lastSeen.After(activityCutoff) {
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

	// Evict to 95% of cap so subsequent inserts don't re-trigger the sort.
	target := t.maxTracked * 95 / 100
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
