package daemon

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/store"
)

// mailIPEntry tracks failed-auth timestamps, successful-login timestamps, the
// mailboxes seen on each side, and suppression state for one IP. The mailbox
// context keeps unrelated successful logins from hiding a mailbox attack.
type mailIPEntry struct {
	times           []time.Time
	succ            []time.Time
	successAccounts map[string][]time.Time
	failedAccounts  map[string][]time.Time
	// goodFirst/goodLast record, per mailbox, the earliest and most recent
	// successful auth from this IP within mailGoodSourceTTL. They outlive the
	// short failure window so an established legitimate sender (e.g. a working
	// POP3 profile) is not mistaken for an attacker when a second misconfigured
	// profile produces a burst of auth failures.
	goodFirst  map[string]time.Time
	goodLast   map[string]time.Time
	suppressed time.Time
	// suspectedSuppressed rate-limits the advisory mail_bruteforce_suspected
	// finding independently of the auto-block clock, so a misconfigured client
	// is surfaced once per window without firing repeatedly, yet a later
	// escalation to a real spray can still reach the auto-block path.
	suspectedSuppressed time.Time
	lastSeen            time.Time
}

// recordGoodAuth notes a successful auth for account at now, maintaining the
// established-sender window. A success after a gap longer than the TTL starts a
// fresh relationship. Caller must hold t.mu.
func (e *mailIPEntry) recordGoodAuth(account string, now time.Time) {
	if account == "" {
		return
	}
	if e.goodFirst == nil {
		e.goodFirst = make(map[string]time.Time)
		e.goodLast = make(map[string]time.Time)
	}
	if last, ok := e.goodLast[account]; !ok || now.Sub(last) > mailGoodSourceTTL {
		e.goodFirst[account] = now
	}
	e.goodLast[account] = now
	if len(e.goodLast) > mailGoodSourceMaxAccountsPerIP {
		e.evictOldestGoodSource()
	}
}

// evictOldestGoodSource drops the least-recently-successful mailbox so a single
// IP's good-source records stay bounded. Caller must hold t.mu.
func (e *mailIPEntry) evictOldestGoodSource() {
	var oldestAcct string
	var oldest time.Time
	for acct, ts := range e.goodLast {
		if oldestAcct == "" || ts.Before(oldest) {
			oldestAcct, oldest = acct, ts
		}
	}
	delete(e.goodLast, oldestAcct)
	delete(e.goodFirst, oldestAcct)
}

// pruneGoodSource drops good-source records whose most recent success is older
// than cutoff (now - mailGoodSourceTTL). Caller must hold t.mu.
func (e *mailIPEntry) pruneGoodSource(cutoff time.Time) {
	for account, last := range e.goodLast {
		if last.Before(cutoff) {
			delete(e.goodLast, account)
			delete(e.goodFirst, account)
		}
	}
}

// establishedGood reports whether this IP is an established legitimate sender
// for account: it authenticated successfully longer ago than the failure window
// (so the current failure burst is not its first contact) and recently enough
// to still be live. Caller must hold t.mu.
func (e *mailIPEntry) establishedGood(account string, now time.Time, window time.Duration) bool {
	last, ok := e.goodLast[account]
	if !ok || now.Sub(last) > mailGoodSourceTTL {
		return false
	}
	return now.Sub(e.goodFirst[account]) >= window
}

// establishedOtherGoodAccounts counts mailboxes other than account for which
// this IP holds established good standing. Same-window successes are not
// established, so a stuffing run that already landed other mailboxes earns
// nothing here. Caller must hold t.mu.
func (e *mailIPEntry) establishedOtherGoodAccounts(account string, now time.Time, window time.Duration) int {
	n := 0
	for acct := range e.goodLast {
		if acct == account {
			continue
		}
		if e.establishedGood(acct, now, window) {
			n++
		}
	}
	return n
}

// establishedGoodConfined reports whether this IP looks like a misconfigured
// legitimate client rather than a brute-forcer: every current failure is
// attributed to a named mailbox, and every one of those failing mailboxes is a
// mailbox this IP holds ESTABLISHED good standing for (it authenticated
// successfully to that same mailbox longer ago than the failure window and
// recently enough to still be live). When true the per-IP signal is downgraded
// to an advisory rather than a firewall block, so a source whose own working
// mailbox now fails on a stale saved password (e.g. POP3 succeeds while IMAP
// fails on the same box) is not locked out.
//
// Good standing is scoped to the (IP, mailbox) identity that earned it: standing
// on mailbox A does NOT vouch for failures on a different mailbox B the IP has
// never signed into. The earlier count-only bound (failing count <= good count)
// was identity-blind and let a source with good standing on N of its own
// mailboxes brute-force N unrelated victim mailboxes indefinitely without ever
// auto-blocking. A fresh same-window "success" is not established, so padding
// earns no downgrade, and the compromise and spray detectors stay fully armed.
// Caller must hold t.mu and must have pruned
// e.times/e.failedAccounts/e.successAccounts to the window.
func (e *mailIPEntry) establishedGoodConfined(now time.Time, window time.Duration) bool {
	failing := len(e.failedAccounts)
	if failing == 0 {
		return false
	}
	named := 0
	for account, times := range e.failedAccounts {
		named += len(times)
		if !e.establishedGood(account, now, window) {
			return false
		}
	}
	// Accountless failures (no user= in the log line) could target anything; a
	// good source's standing must not hide them.
	return named == len(e.times)
}

func normalizeMailAuthAccount(account string) string {
	local, domain, ok := strings.Cut(account, "@")
	if !ok || local == "" || domain == "" {
		return account
	}
	return local + "@" + strings.ToLower(domain)
}

// recentGoodCount returns how many distinct mailboxes this IP succeeded on
// recently enough to still be on record (last success within
// mailGoodSourceTTL), regardless of whether that standing has aged past the
// failure window. Unlike establishedGood it does not require the
// relationship to predate the burst, so it recognizes a legitimate sender whose
// standing is only seconds old -- a cold-started daemon before persisted
// standing re-ages, or a customer returning after the snapshot expired. Caller
// must hold t.mu.
func (e *mailIPEntry) recentGoodCount(now time.Time) int {
	n := 0
	for _, last := range e.goodLast {
		if now.Sub(last) <= mailGoodSourceTTL {
			n++
		}
	}
	return n
}

// looksLikeFreshGoodSourceFP reports the cold-start/misconfiguration
// false-positive shape: the same confined, named, non-cracking failure set that
// establishedGoodConfined downgrades, but bounded by the IP's recent-success
// footprint instead of its established (aged) one. It is true exactly when the
// only reason the burst was not downgraded to an advisory is that the source's
// good standing is too fresh to have aged past the window. The auto-block still
// fires -- a fresh success cannot be trusted to grant a brute-force bypass, or a
// padding login would buy an attacker slack -- but the finding is annotated so
// an operator can spot a likely false positive without reconstructing the mail
// log by hand. Caller must hold t.mu and must have pruned the window state.
func (e *mailIPEntry) looksLikeFreshGoodSourceFP(now time.Time, window time.Duration) bool {
	failing := len(e.failedAccounts)
	if failing == 0 {
		return false
	}
	named := 0
	for account, times := range e.failedAccounts {
		named += len(times)
		if e.isCrackInProgress(account, now, window) {
			return false
		}
	}
	if named != len(e.times) {
		return false
	}
	return failing <= e.recentGoodCount(now)
}

// mailFailTarget is one mailbox this IP's in-window failures hit, with the
// failure count for that mailbox.
type mailFailTarget struct {
	Account string
	Count   int
}

// failTargets summarizes which mailboxes this IP's in-window failures targeted.
// It returns the per-mailbox counts sorted by count (desc) then account name
// (asc) for deterministic output, plus how many failures carried no mailbox
// (dovecot lines with no user=). Caller must hold t.mu and must have pruned
// e.times and e.failedAccounts to the window.
func (e *mailIPEntry) failTargets() ([]mailFailTarget, int) {
	named := 0
	targets := make([]mailFailTarget, 0, len(e.failedAccounts))
	for account, times := range e.failedAccounts {
		named += len(times)
		targets = append(targets, mailFailTarget{Account: account, Count: len(times)})
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Count != targets[j].Count {
			return targets[i].Count > targets[j].Count
		}
		return targets[i].Account < targets[j].Account
	})
	return targets, len(e.times) - named
}

// Unsafe account bytes are hex-escaped so a crafted user= value cannot add
// fake target separators, new alert lines, or path-looking tokens.
func formatMailFailTargetAccount(account string) string {
	truncated := false
	if len(account) > maxMailTargetAccountDisplayBytes {
		account = account[:maxMailTargetAccountDisplayBytes]
		truncated = true
	}
	if isPlainMailFailTargetAccount(account) {
		if truncated {
			return account + "..."
		}
		return account
	}
	var b strings.Builder
	b.WriteString(`account="`)
	for i := 0; i < len(account); i++ {
		c := account[i]
		if isPlainMailFailTargetAccountByte(c) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, `\x%02x`, c)
	}
	if truncated {
		b.WriteString("...")
	}
	b.WriteByte('"')
	return b.String()
}

func isPlainMailFailTargetAccount(account string) bool {
	if account == "" {
		return false
	}
	for i := 0; i < len(account); i++ {
		if !isPlainMailFailTargetAccountByte(account[i]) {
			return false
		}
	}
	return true
}

func isPlainMailFailTargetAccountByte(c byte) bool {
	return c >= 'a' && c <= 'z' ||
		c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' ||
		strings.ContainsRune("@._+-=%*", rune(c))
}

// formatMailFailTargets renders the target summary for a mail brute-force
// finding: the mailboxes hit with their failure counts (at most max named, the
// rest collapsed into "(+N more)") and a count of failures that named no
// mailbox. Returns "" when there is nothing to report.
func formatMailFailTargets(targets []mailFailTarget, accountless, max int) string {
	if len(targets) == 0 && accountless <= 0 {
		return ""
	}
	listed := targets
	remainder := 0
	if max > 0 && len(targets) > max {
		listed = targets[:max]
		remainder = len(targets) - max
	}
	var b strings.Builder
	b.WriteString("Targets: ")
	for i, tg := range listed {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s (%d)", formatMailFailTargetAccount(tg.Account), tg.Count)
	}
	if remainder > 0 {
		fmt.Fprintf(&b, " (+%d more)", remainder)
	}
	if accountless > 0 {
		if len(listed) > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%d with no mailbox", accountless)
	}
	return b.String()
}

// successDominant reports whether this IP behaves like a legit busy client
// rather than a brute-forcer: it has successful logins in the window, at least
// as many successes as failures, and the successful mailboxes explain the failed
// mailbox set. Caller must hold t.mu and must have pruned the slices and account
// maps to the current window first.
func (e *mailIPEntry) successDominant() bool {
	if len(e.succ) == 0 || len(e.succ) < len(e.times) || len(e.failedAccounts) == 0 {
		return false
	}
	named := 0
	for account, failures := range e.failedAccounts {
		named += len(failures)
		if len(e.successAccounts[account]) < len(failures) {
			return false
		}
	}
	return named == len(e.times)
}

func (e *mailIPEntry) accountSuccessDominant(account string) bool {
	failures := len(e.failedAccounts[account])
	return failures > 0 && len(e.successAccounts[account]) >= failures
}

// isCrackInProgress reports whether same-account successes mixed with failures
// look like a guessing breakthrough rather than a flaky legitimate client.
//
// An account the IP holds established good standing for (it has owned the
// mailbox longer than the window) is exempt: a mix of successes and failures
// there is an intermittent or stale-on-one-device client, the same mistype
// signal RecordSuccess uses to suppress compromise. Only a fresh, non-established
// in-window success that does not dominate the failures is treated as a crack:
// that is the attacker-just-guessed-it shape. Caller must hold t.mu.
func (e *mailIPEntry) isCrackInProgress(account string, now time.Time, window time.Duration) bool {
	if e.establishedGood(account, now, window) {
		return false
	}
	cutoff := now.Add(-window)
	for _, ts := range e.successAccounts[account] {
		if ts.After(cutoff) {
			return !e.accountSuccessDominant(account)
		}
	}
	return false
}

// goodSourceTimes is the persisted established-sender window for one mailbox:
// the earliest and most recent successful auth from an IP.
type goodSourceTimes struct {
	First time.Time
	Last  time.Time
}

// goodSourceSnapshot maps ip -> account -> goodSourceTimes. It is persisted
// across daemon restarts so established good standing survives a restart and the
// post-restart cold-start window does not re-open the brute-force false-positive
// window (a customer's working profile would otherwise have to re-authenticate
// and re-age past the failure window before its stale-password profile stops
// being mistaken for an attacker).
type goodSourceSnapshot map[string]map[string]goodSourceTimes

// ExportGoodSource snapshots the established-sender records for persistence.
// Only good-source state is exported; short-lived failure/success window state
// is intentionally not persisted.
func (t *mailAuthTracker) ExportGoodSource() goodSourceSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	snap := make(goodSourceSnapshot)
	for ip, e := range t.ips {
		if len(e.goodLast) == 0 {
			continue
		}
		accts := make(map[string]goodSourceTimes, len(e.goodLast))
		for acct, last := range e.goodLast {
			accts[acct] = goodSourceTimes{First: e.goodFirst[acct], Last: last}
		}
		snap[ip] = accts
	}
	return snap
}

// LoadGoodSource seeds established-sender records from a persisted snapshot,
// dropping any whose most recent success is already older than the good-source
// TTL. Intended for one-time startup seeding; a record newer than the snapshot
// (a success already observed this run) keeps its Last time, while colliding
// normalized mailbox records keep the earliest First time.
func (t *mailAuthTracker) LoadGoodSource(snap goodSourceSnapshot, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := now.Add(-mailGoodSourceTTL)
	for ip, accts := range snap {
		for acct, ts := range accts {
			acct = normalizeMailAuthAccount(acct)
			if ip == "" || acct == "" || !validGoodSourceTimes(ts, cutoff) {
				continue
			}
			e, ok := t.ips[ip]
			if !ok {
				e = &mailIPEntry{}
				t.ips[ip] = e
			}
			if e.goodFirst == nil {
				e.goodFirst = make(map[string]time.Time)
				e.goodLast = make(map[string]time.Time)
			}
			if cur, ok := e.goodFirst[acct]; !ok || ts.First.Before(cur) {
				e.goodFirst[acct] = ts.First
			}
			if cur, ok := e.goodLast[acct]; !ok || ts.Last.After(cur) {
				e.goodLast[acct] = ts.Last
			}
			if e.goodLast[acct].After(e.lastSeen) {
				e.lastSeen = e.goodLast[acct]
			}
			if len(e.goodLast) > mailGoodSourceMaxAccountsPerIP {
				e.evictOldestGoodSource()
			}
		}
	}
	t.enforceMaxTracked()
}

func validGoodSourceTimes(ts goodSourceTimes, cutoff time.Time) bool {
	return !ts.First.IsZero() &&
		!ts.Last.IsZero() &&
		!ts.First.After(ts.Last) &&
		!ts.Last.Before(cutoff)
}

// loadMailGoodSource seeds the tracker before log readers start, so first
// post-startup auth failures see the persisted standing instead of cold state.
func (d *Daemon) loadMailGoodSource() {
	if d.mailAuthTracker == nil {
		return
	}
	if sdb := store.Global(); sdb != nil {
		snap, err := sdb.LoadMailGoodSource()
		if err != nil {
			csmlog.Warn("mail good-source load failed", "err", err)
			return
		}
		d.mailAuthTracker.LoadGoodSource(storeToGoodSourceSnapshot(snap), d.mailAuthTracker.now())
	}
}

// persistMailGoodSource writes the tracker's established good-source snapshot to
// the store so it survives a restart. No-op when the store or tracker is absent.
func (d *Daemon) persistMailGoodSource() {
	if d.mailAuthTracker == nil {
		return
	}
	if sdb := store.Global(); sdb != nil {
		snap := goodSourceSnapshotToStore(d.mailAuthTracker.ExportGoodSource())
		if err := sdb.SaveMailGoodSource(snap); err != nil {
			csmlog.Warn("mail good-source persistence failed", "err", err)
		}
	}
}

func storeToGoodSourceSnapshot(in map[string]map[string]store.GoodSourcePair) goodSourceSnapshot {
	out := make(goodSourceSnapshot, len(in))
	for ip, accts := range in {
		m := make(map[string]goodSourceTimes, len(accts))
		for a, p := range accts {
			m[a] = goodSourceTimes{First: p.First, Last: p.Last}
		}
		out[ip] = m
	}
	return out
}

func goodSourceSnapshotToStore(in goodSourceSnapshot) map[string]map[string]store.GoodSourcePair {
	out := make(map[string]map[string]store.GoodSourcePair, len(in))
	for ip, accts := range in {
		m := make(map[string]store.GoodSourcePair, len(accts))
		for a, ts := range accts {
			m[a] = store.GoodSourcePair{First: ts.First, Last: ts.Last}
		}
		out[ip] = m
	}
	return out
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

// mailBackendDegradedThreshold is how many auth-backend failure observations
// (dovecot unable to reach the credential backend, e.g. cPanel's cpdoveauthd)
// within the tracker window mark the mail auth subsystem as degraded. A healthy
// host produces zero of these; a backend outage produces thousands. While
// degraded, every login fails regardless of credentials, so the per-IP and
// per-subnet brute signals are suppressed to avoid auto-blocking legitimate
// users en masse.
const mailBackendDegradedThreshold = 10

// mailGoodSourceTTL is how long a successful authentication keeps an (IP,
// mailbox) pair on record as an established legitimate sender. A real owner
// authenticates successfully at least this often; once the last success ages
// past the TTL the standing is forgotten, so an IP cannot be permanently
// whitelisted by a single old success.
const mailGoodSourceTTL = 24 * time.Hour

// mailGoodSourceMaxAccountsPerIP caps how many distinct mailboxes one IP keeps
// good-source records for. A carrier-grade NAT can carry many legitimate
// mailboxes; the cap bounds memory without affecting detection (eviction is
// least-recently-successful first).
const mailGoodSourceMaxAccountsPerIP = 256

// mailEstablishedSourceAccounts is how many OTHER mailboxes an IP must hold
// established good standing on before a compromise finding for one more
// mailbox is downgraded to an advisory (office/agency device pattern).
const mailEstablishedSourceAccounts = 2

// maxMailTargetsListed caps how many mailboxes a brute-force finding names
// before collapsing the rest into a "(+N more)" suffix, so a wide spray does
// not dump dozens of names into one alert.
const maxMailTargetsListed = 5

// maxMailTargetAccountDisplayBytes bounds attacker-controlled account text in
// brute-force Details while keeping normal mailbox names intact.
const maxMailTargetAccountDisplayBytes = 128

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

	// backendErr holds recent auth-backend failure timestamps. While the
	// windowed count is at or above mailBackendDegradedThreshold the auth
	// subsystem is treated as down and brute/subnet auto-block signals are
	// suppressed. backendWarnUntil rate-limits the operator warning to one per
	// suppression window.
	backendErr       []time.Time
	backendWarnUntil time.Time

	// backendDownFn, when set, reports whether the active socket probe currently
	// sees the mail auth backend down. It augments the log-derived backendErr
	// heuristic so suppression also triggers on the authoritative probe signal.
	backendDownFn func() bool
}

// SetBackendDownCheck installs the active-probe callback the tracker consults to
// learn whether the mail auth backend is down. When it returns true, brute-force
// and subnet auto-block are suppressed. Set once at startup before log readers
// begin.
func (t *mailAuthTracker) SetBackendDownCheck(fn func() bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.backendDownFn = fn
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
	account = normalizeMailAuthAccount(account)
	t.mu.Lock()
	defer t.mu.Unlock()

	t.recordCalls++

	now := t.now()
	cutoff := now.Add(-t.window)
	var findings []alert.Finding

	// During an auth-backend outage every login fails regardless of password, so
	// the failure-rate signals are meaningless and would mass-block real users.
	// Either the log-derived heuristic or the authoritative socket probe trips it.
	degraded := t.backendDegraded(now)
	if !degraded && t.backendDownFn != nil {
		degraded = t.backendDownFn()
	}

	// --- Per-IP tracker ---
	e, ok := t.ips[ip]
	if !ok {
		e = &mailIPEntry{}
		t.ips[ip] = e
	}
	e.times = pruneTimes(e.times, cutoff)
	pruneMailAccountTimes(e.failedAccounts, cutoff)
	e.times = append(e.times, now)
	e.failedAccounts = appendMailAccountTime(e.failedAccounts, account, now)
	e.lastSeen = now

	if t.perIPThreshold > 0 && len(e.times) >= t.perIPThreshold {
		e.succ = pruneTimes(e.succ, cutoff)
		pruneMailAccountTimes(e.successAccounts, cutoff)
		if !e.successDominant() && !degraded {
			switch {
			case e.establishedGoodConfined(now, t.window):
				// Established good source fat-fingering a confined set of its own
				// mailboxes: surface for visibility but do not auto-block, so a
				// stale saved password does not lock out a real customer. A real
				// attack from the same source still blocks via the compromise and
				// spray detectors. Rate-limited on its own clock so escalation to a
				// wider spray can still reach the block path below.
				if now.Before(e.suspectedSuppressed) {
					break
				}
				e.suspectedSuppressed = now.Add(t.suppression)
				details := "Failures are confined to a few named mailboxes from a source with established successful mail auth history; likely a stale saved password, not a brute-force. Visibility only - no auto-block. Compromise and spray detectors remain active."
				targets, accountless := e.failTargets()
				if targetSummary := formatMailFailTargets(targets, accountless, maxMailTargetsListed); targetSummary != "" {
					details += " " + targetSummary + "."
				}
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "mail_bruteforce_suspected",
					Message: fmt.Sprintf("Suspected mail misconfiguration from %s: %d failed auths in %v from an established good source (not auto-blocked)",
						ip, len(e.times), t.window),
					Details:   details,
					Timestamp: now,
					SourceIP:  ip,
				})
			case !now.Before(e.suppressed):
				e.suppressed = now.Add(t.suppression)
				details := "Real-time detection of dovecot imap/pop3/managesieve auth failures."
				if e.looksLikeFreshGoodSourceFP(now, t.window) {
					details += " Note: this source has recent successful mail auth for one or more other mailboxes, so the failures may be a misconfigured client with a stale saved password rather than an attack. Verify before treating it as a confirmed brute-force."
				}
				targets, accountless := e.failTargets()
				if targetSummary := formatMailFailTargets(targets, accountless, maxMailTargetsListed); targetSummary != "" {
					details += " " + targetSummary + "."
				}
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "mail_bruteforce",
					Message: fmt.Sprintf("Mail auth brute force from %s: %d failed auths in %v",
						ip, len(e.times), t.window),
					Details:   details,
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

		if t.subnetThreshold > 0 && len(s.ips) >= t.subnetThreshold && !now.Before(s.suppressed) && !degraded {
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

		if t.accountSprayThreshold > 0 && len(a.ips) >= t.accountSprayThreshold && !now.Before(a.suppressed) {
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

// RecordBackendFailure records one auth-backend failure observation (dovecot
// could not reach the credential backend). It returns a one-shot operator
// warning the first time the subsystem crosses into "degraded" within a
// suppression window, so an outage is visible rather than silently pausing
// detection. Callers feed this from log lines matched by isMailAuthBackendError.
func (t *mailAuthTracker) RecordBackendFailure() []alert.Finding {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.recordBackendFailureTime(now)
	if len(t.backendErr) < mailBackendDegradedThreshold || now.Before(t.backendWarnUntil) {
		return nil
	}
	t.backendWarnUntil = now.Add(t.suppression)
	t.findingsEmitted++
	return []alert.Finding{{
		Severity: alert.Warning,
		Check:    "mail_auth_backend_degraded",
		Message: fmt.Sprintf("Mail auth backend degraded: %d backend failures in %v; mail brute-force auto-block paused",
			len(t.backendErr), t.window),
		Details:   "Dovecot could not reach the credential backend (e.g. cpdoveauthd). Logins fail regardless of password, so brute-force and subnet auto-blocks are paused to avoid locking out legitimate users. Investigate the auth daemon.",
		Timestamp: now,
	}}
}

// recordBackendFailureTime keeps only the newest observations needed to prove
// the degraded invariant. Backend outages can flood logs; tracking more than
// the threshold would add memory pressure without changing detection.
func (t *mailAuthTracker) recordBackendFailureTime(now time.Time) {
	t.backendErr = pruneTimes(t.backendErr, now.Add(-t.window))
	if len(t.backendErr) == 0 {
		t.backendErr = nil
	}
	if len(t.backendErr) >= mailBackendDegradedThreshold {
		const keep = mailBackendDegradedThreshold - 1
		if cap(t.backendErr) > mailBackendDegradedThreshold {
			recent := make([]time.Time, mailBackendDegradedThreshold)
			copy(recent, t.backendErr[len(t.backendErr)-keep:])
			recent[keep] = now
			t.backendErr = recent
			return
		}
		copy(t.backendErr, t.backendErr[len(t.backendErr)-keep:])
		t.backendErr = t.backendErr[:mailBackendDegradedThreshold]
		t.backendErr[keep] = now
		return
	}
	t.backendErr = append(t.backendErr, now)
}

// backendDegraded reports whether the mail auth backend looks down: at least
// mailBackendDegradedThreshold backend-failure observations within the window.
// Caller must hold t.mu.
func (t *mailAuthTracker) backendDegraded(now time.Time) bool {
	t.backendErr = pruneTimes(t.backendErr, now.Add(-t.window))
	if len(t.backendErr) == 0 {
		t.backendErr = nil
	}
	return len(t.backendErr) >= mailBackendDegradedThreshold
}

func pruneMailAccountTimes(accounts map[string][]time.Time, cutoff time.Time) {
	for account, times := range accounts {
		times = pruneTimes(times, cutoff)
		if len(times) == 0 {
			delete(accounts, account)
			continue
		}
		accounts[account] = times
	}
}

func appendMailAccountTime(accounts map[string][]time.Time, account string, ts time.Time) map[string][]time.Time {
	if account == "" {
		return accounts
	}
	if accounts == nil {
		accounts = make(map[string][]time.Time)
	}
	accounts[account] = append(accounts[account], ts)
	return accounts
}

// RecordSuccess processes a successful mail login. Emits mail_account_compromised
// when the successful IP has repeated recent failed auths for the same account
// and that mailbox is failure-dominant from this IP. Prior successful logins for
// the same mailbox look like a legit client that merely mistyped, so they are
// not flagged.
//
// ip and account MUST both be non-empty. Caller filters infra/private/loopback
// IPs before invoking.
func (t *mailAuthTracker) RecordSuccess(ip, account string) []alert.Finding {
	if ip == "" || account == "" {
		return nil
	}
	account = normalizeMailAuthAccount(account)
	t.mu.Lock()
	defer t.mu.Unlock()
	// Successes create per-IP entries too; keep the tracker bounded on every
	// path (runs under the held lock, before Unlock).
	defer t.enforceMaxTracked()

	now := t.now()
	cutoff := now.Add(-t.window)

	// Track per-IP successes unconditionally. The current success is recorded at
	// function exit so the compromise gate can distinguish prior legit activity
	// from a padding login that belongs to the event being classified.
	e, ok := t.ips[ip]
	if !ok {
		e = &mailIPEntry{}
		t.ips[ip] = e
	}
	e.succ = pruneTimes(e.succ, cutoff)
	pruneMailAccountTimes(e.successAccounts, cutoff)
	pruneMailAccountTimes(e.failedAccounts, cutoff)
	// A guessed-password success should not train the long-lived good-source cache.
	recordGoodSource := true
	defer func() {
		e.succ = append(e.succ, now)
		e.successAccounts = appendMailAccountTime(e.successAccounts, account, now)
		if recordGoodSource {
			e.recordGoodAuth(account, now)
		}
		e.lastSeen = now
	}()

	a, ok := t.accounts[account]
	if !ok {
		return nil
	}
	for ipKey, ts := range a.ips {
		if ts.Before(cutoff) {
			delete(a.ips, ipKey)
		}
	}
	if _, failedRecently := a.ips[ip]; !failedRecently {
		return nil
	}
	// A mailbox that already succeeds from this IP is a legit owner who mistyped,
	// not a takeover. Genuine password guessing is failure-dominant for the same
	// mailbox.
	e.times = pruneTimes(e.times, cutoff)
	targetFailures := len(e.failedAccounts[account])
	if targetFailures < 2 || e.accountSuccessDominant(account) || e.establishedGood(account, now, t.window) {
		return nil
	}
	recordGoodSource = false
	if now.Before(a.compromiseSuppressed) {
		return nil
	}
	a.compromiseSuppressed = now.Add(t.suppression)
	_, compDomain := alert.SplitEmail(account)
	t.findingsEmitted++
	severity := alert.Critical
	message := fmt.Sprintf("Mail account compromise: successful login for %s from %s after recent auth failures",
		account, ip)
	details := "Attacker succeeded after repeated failed attempts from the same IP for this mailbox. Rotate password and revoke sessions."
	// An IP with established standing on several other mailboxes is far more
	// likely a shared office or agency device carrying one stale credential
	// than a takeover: real credential attacks come from sources with no
	// legitimate multi-mailbox history on this host. Keep the finding for
	// visibility but downgrade it below the auto-block bar.
	if n := e.establishedOtherGoodAccounts(account, now, t.window); n >= mailEstablishedSourceAccounts {
		severity = alert.High
		message += " (established multi-mailbox source)"
		details = fmt.Sprintf("Source IP holds established successful logins to %d other mailboxes on this host, so this is more likely a shared office or agency device with a stale credential than a takeover. Verify with the customer before acting; not auto-blocked.", n)
	}
	return []alert.Finding{{
		Severity:  severity,
		Check:     "mail_account_compromised",
		Message:   message,
		Details:   details,
		Timestamp: now,
		SourceIP:  ip,
		Domain:    compDomain,
		Mailbox:   account,
	}}
}

// Purge removes stale tracker entries. Good-source-only IPs live until
// mailGoodSourceTTL; failure and short success history uses the detector window.
// Called from a background goroutine every minute.
func (t *mailAuthTracker) Purge() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	activityCutoff := now.Add(-(t.window + t.suppression))
	windowCutoff := now.Add(-t.window)

	goodCutoff := now.Add(-mailGoodSourceTTL)
	for k, e := range t.ips {
		e.times = pruneTimes(e.times, windowCutoff)
		e.succ = pruneTimes(e.succ, windowCutoff)
		pruneMailAccountTimes(e.successAccounts, windowCutoff)
		pruneMailAccountTimes(e.failedAccounts, windowCutoff)
		e.pruneGoodSource(goodCutoff)
		if len(e.times) == 0 && len(e.succ) == 0 && len(e.successAccounts) == 0 &&
			len(e.failedAccounts) == 0 && len(e.goodLast) == 0 && !e.lastSeen.After(activityCutoff) {
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
	t.backendErr = pruneTimes(t.backendErr, windowCutoff)
	if len(t.backendErr) == 0 {
		t.backendErr = nil
	}
}

// enforceMaxTracked evicts the least-recently-seen entries until total tracked
// state is <= 95% of maxTracked. Batch target avoids re-sorting on every
// subsequent insert. Caller must hold t.mu.
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

// isMailAuthBackendError reports whether a dovecot log line shows the auth
// backend itself failing (could not verify ANY credential), as opposed to an
// ordinary wrong-password failure. During such an outage every login fails, so
// these events must drive the degraded gate, not the brute-force counters.
func isMailAuthBackendError(line string) bool {
	if isMailAuthLine(line) {
		return false
	}
	msg := dovecotServiceMessage(line)
	if msg == "" {
		return false
	}
	detail := msg
	if strings.HasPrefix(detail, "auth-worker") {
		detail = authWorkerDetail(detail)
	}
	lowerDetail := strings.ToLower(detail)
	if strings.Contains(lowerDetail, "cpdoveauthd.sock") {
		return strings.Contains(lowerDetail, "failed to connect") ||
			strings.Contains(lowerDetail, "socket error") ||
			strings.Contains(lowerDetail, "connection refused")
	}
	if strings.Contains(lowerDetail, "temporary authentication failure") {
		return strings.HasPrefix(msg, "auth-worker") || strings.Contains(strings.ToLower(msg), "auth:")
	}
	if !strings.HasPrefix(msg, "auth-worker") {
		return false
	}
	return strings.Contains(lowerDetail, "connection refused") ||
		strings.Contains(lowerDetail, "internal error")
}

func dovecotServiceMessage(line string) string {
	tagEnd := strings.Index(line, ": ")
	if tagEnd < 0 {
		return ""
	}
	prefix := line[:tagEnd]
	tagStart := strings.LastIndexAny(prefix, " \t")
	if tagStart >= 0 {
		prefix = prefix[tagStart+1:]
	}
	if !isDovecotProgramTag(prefix) {
		return ""
	}
	return strings.TrimSpace(line[tagEnd+2:])
}

func isDovecotProgramTag(tag string) bool {
	if tag == "dovecot" {
		return true
	}
	const prefix = "dovecot["
	if !strings.HasPrefix(tag, prefix) || !strings.HasSuffix(tag, "]") {
		return false
	}
	pid := tag[len(prefix) : len(tag)-1]
	if pid == "" {
		return false
	}
	for i := 0; i < len(pid); i++ {
		if pid[i] < '0' || pid[i] > '9' {
			return false
		}
	}
	return true
}

func authWorkerDetail(msg string) string {
	parenDepth := 0
	angleDepth := 0
	for i := 0; i < len(msg); i++ {
		switch msg[i] {
		case '(':
			if angleDepth == 0 {
				parenDepth++
			}
		case ')':
			if angleDepth == 0 && parenDepth > 0 {
				parenDepth--
			}
		case '<':
			if parenDepth == 0 {
				angleDepth++
			}
		case '>':
			if parenDepth == 0 && angleDepth > 0 {
				angleDepth--
			}
		case ':':
			if parenDepth == 0 && angleDepth == 0 {
				return strings.TrimSpace(msg[i+1:])
			}
		}
	}
	return ""
}

// isMailAuthLine returns true for dovecot imap/pop3/managesieve login events.
func isMailAuthLine(line string) bool {
	msg := dovecotServiceMessage(line)
	return strings.HasPrefix(msg, "imap-login:") ||
		strings.HasPrefix(msg, "pop3-login:") ||
		strings.HasPrefix(msg, "managesieve-login:")
}

// dovecotLoginSucceeded reports whether a dovecot imap/pop3/managesieve line
// records a successful login. Dovecot emits two success formats depending on
// version and configuration:
//
//	"<proto>-login: Logged in: user=<...>"   (observed on production cPanel)
//	"<proto>-login: Login: user=<...>"        (classic dovecot)
//
// Both the mailbrute compromise detector and the geo new-country detector must
// accept BOTH; keying each consumer off a different single marker left one of
// them silently dead on whichever format the deployment happened to use.
func dovecotLoginSucceeded(line string) bool {
	msg := dovecotServiceMessage(line)
	return strings.HasPrefix(msg, "imap-login: Logged in: user=<") ||
		strings.HasPrefix(msg, "imap-login: Login: user=<") ||
		strings.HasPrefix(msg, "pop3-login: Logged in: user=<") ||
		strings.HasPrefix(msg, "pop3-login: Login: user=<") ||
		strings.HasPrefix(msg, "managesieve-login: Logged in: user=<") ||
		strings.HasPrefix(msg, "managesieve-login: Login: user=<")
}

// extractMailLoginEvent parses a dovecot login line and returns
// (ip, account, success). Returns empty strings and false on parse failure.
//
// Real dovecot wire format (validated against production logs):
//
//	Success: "imap-login: Logged in: user=<alice@x.ro>, method=PLAIN, rip=..."
//	Failure: "imap-login: Login aborted: ... (auth failed, N attempts ...): user=<...>, method=..., rip=..."
//
// Success is matched via dovecotLoginSucceeded so both dovecot success formats
// count (an earlier version keyed only off "Logged in" and silently skipped
// every classic-format login, which broke RecordSuccess compromise detection).
// The failure marker is "(auth failed" with the opening paren, which
// distinguishes real auth failures from Login-aborted reasons like
// "no auth attempts" or TLS handshake errors.
func extractMailLoginEvent(line string) (ip, account string, success bool) {
	switch {
	case dovecotLoginSucceeded(line):
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
