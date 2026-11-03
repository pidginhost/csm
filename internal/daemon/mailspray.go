package daemon

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// sprayMode says what the spray rules do with a verdict. Evidence and trust
// are recorded in every mode, so trust keeps closing the slow-brute hole even
// with the rules off.
type sprayMode uint8

const (
	sprayOff sprayMode = iota
	sprayObserve
	sprayEnforce
)

func parseSprayMode(s string) sprayMode {
	switch s {
	case "observe":
		return sprayObserve
	case "enforce":
		return sprayEnforce
	}
	return sprayOff
}

type sprayConfig struct {
	Mode             sprayMode
	Window           time.Duration // evidence and trust memory; 0 disables the component
	BreadthMailboxes int           // untrusted mailboxes that block; 0 disables
	MissingNetworks  int           // networks that must try a missing name first; 0 disables
	TrustAge         time.Duration // trust counts only after this age
	Suppression      time.Duration // least gap between verdicts for one IP
	MaxIPs           int           // tracked IP cap
}

type sprayRule string

const (
	sprayRuleMissingMailbox       sprayRule = "missing_mailbox"
	sprayRuleBreadth              sprayRule = "breadth"
	sprayRuleCompromise           sprayRule = "compromise"
	sprayRuleWeakCompromise       sprayRule = "weak_compromise"
	sprayRuleSingleMailboxSuccess sprayRule = "single_mailbox_success"
)

type sprayVerdict struct {
	Rule     sprayRule
	Block    bool     // missing_mailbox, breadth, and compromise unless downgraded
	Mailbox  string   // the login's mailbox (success rules) or the missing one
	Targets  []string // untrusted names in memory, sorted; "" is an accountless failure
	Extra    int      // untrusted names beyond Targets
	Networks int      // networks that tried the missing name
}

const (
	maxSprayNamesPerIP         = 32
	maxSprayTrustPerIP         = mailGoodSourceMaxAccountsPerIP
	maxSprayCorroborationNames = 20000
	maxSprayNetworksPerName    = 50
)

type sprayFailure struct {
	last  time.Time
	count int // failures since the name was last idle for a whole window
	exist mailboxExistence
}

type sprayTrust struct{ first, last time.Time }

type sprayIP struct {
	failed                    map[string]sprayFailure
	trust                     map[string]sprayTrust
	suppressedUntil           time.Time
	compromiseSuppressedUntil time.Time
	verdictAt                 time.Time
	lastSeen                  time.Time
}

// sprayName is the corroboration for one missing mailbox name: which networks
// tried it and when.
type sprayName struct {
	networks map[string]time.Time
	last     time.Time
}

// mailSpray is the long-memory login spray detector shared by the SMTP and
// IMAP/POP trackers. Trackers call it while holding their own lock, so it
// must never call back into a tracker or take any other lock.
//
// Mailbox names are taken as given: callers pass them through
// normalizeSprayMailbox once, at their boundary.
type mailSpray struct {
	mu    sync.Mutex
	cfg   sprayConfig
	now   func() time.Time
	ips   map[string]*sprayIP
	names map[string]*sprayName
}

func newMailSpray(cfg sprayConfig, now func() time.Time) *mailSpray {
	return &mailSpray{
		cfg:   cfg,
		now:   now,
		ips:   make(map[string]*sprayIP),
		names: make(map[string]*sprayName),
	}
}

// SetConfig applies a reloaded config. Turning the component off drops its
// memory.
func (m *mailSpray) SetConfig(cfg sprayConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
	if cfg.Window <= 0 {
		clear(m.ips)
		clear(m.names)
		return
	}
	m.evictIPs("", m.now())
}

func (m *mailSpray) Mode() sprayMode {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.Window <= 0 {
		return sprayOff
	}
	return m.cfg.Mode
}

// Failure records a failed login on a normalised mailbox ("" when the log
// names none) and returns a block verdict for rule 2 or rule 3.
func (m *mailSpray) Failure(ip, mailbox string, exist mailboxExistence) *sprayVerdict {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.Window <= 0 {
		return nil
	}
	if mailbox == "" {
		exist = mailboxExistenceUnknown
	}
	now := m.now()
	e := m.touch(ip, now)
	stored := e.recordFailure(mailbox, exist, now, m.cfg.Window)
	networks := 0
	if exist == mailboxMissing {
		networks = m.corroborate(mailbox, ip, now)
	}
	m.evictIPs(ip, now)
	if m.cfg.Mode == sprayOff || now.Before(e.suppressedUntil) {
		return nil
	}

	untrusted := m.untrusted(e, now)
	var v *sprayVerdict
	switch {
	case m.cfg.MissingNetworks > 0 && exist == mailboxMissing &&
		networks >= m.cfg.MissingNetworks && m.agedTrustCount(e, "", now) == 0:
		v = m.verdict(e, sprayRuleMissingMailbox, true, mailbox, untrusted, now)
		v.Networks = networks
	case m.cfg.BreadthMailboxes > 0 && m.breadth(e, mailbox, stored, untrusted, now):
		v = m.verdict(e, sprayRuleBreadth, true, "", untrusted, now)
	default:
		return nil
	}
	e.suppressedUntil = now.Add(m.cfg.Suppression)
	return v
}

// breadth reports whether the IP's untrusted names reach the rule 3 bar. A
// name refused at the per-IP cap still counts, and a full IP satisfies any
// bar above the cap.
func (m *mailSpray) breadth(e *sprayIP, mailbox string, stored bool, untrusted []string, now time.Time) bool {
	n := len(untrusted)
	if !stored && !m.agedTrust(e, mailbox, now) {
		n++
	}
	return n >= min(m.cfg.BreadthMailboxes, maxSprayNamesPerIP)
}

// Success records a successful login on a normalised mailbox. clean is true
// when the login earned or refreshed trust. A login that follows failures on
// other untrusted mailboxes earns nothing and may be a compromise.
func (m *mailSpray) Success(ip, mailbox string) (clean bool, v *sprayVerdict) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.Window <= 0 || mailbox == "" {
		return false, nil
	}
	now := m.now()
	e := m.touch(ip, now)
	defer m.evictIPs(ip, now)
	if m.agedTrust(e, mailbox, now) {
		t := e.trust[mailbox]
		t.last = now
		e.trust[mailbox] = t
		return true, nil
	}

	untrusted := m.untrusted(e, now)
	others := slices.DeleteFunc(slices.Clone(untrusted), func(n string) bool { return n == mailbox })
	if len(others) == 0 {
		hadTrust := m.recordTrust(e, mailbox, now)
		// 4d fires once per trust relationship; later logins while the new
		// trust ages are the same user.
		if m.cfg.Mode == sprayOff || hadTrust || e.failuresInWindow(mailbox, now, m.cfg.Window) < 2 {
			return true, nil
		}
		return true, m.verdict(e, sprayRuleSingleMailboxSuccess, false, mailbox, untrusted, now)
	}

	if m.cfg.Mode == sprayOff || now.Before(e.compromiseSuppressedUntil) {
		return false, nil
	}
	rule, block := sprayRuleWeakCompromise, false
	if slices.ContainsFunc(others, func(n string) bool { return m.corroboratedMissing(e, n, now) }) {
		rule = sprayRuleCompromise
		block = m.agedTrustCount(e, mailbox, now) < mailEstablishedSourceAccounts
	}
	e.compromiseSuppressedUntil = now.Add(m.cfg.Suppression)
	return false, m.verdict(e, rule, block, mailbox, untrusted, now)
}

// TrustedAll reports whether the IP holds aged trust on every one of the
// normalised mailboxes. An empty list is not trusted.
func (m *mailSpray) TrustedAll(ip string, mailboxes []string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.ips[ip]
	if m.cfg.Window <= 0 || e == nil || len(mailboxes) == 0 {
		return false
	}
	now := m.now()
	for _, mb := range mailboxes {
		if !m.agedTrust(e, mb, now) {
			return false
		}
	}
	return true
}

// Purge drops failures, trust and corroboration older than the window.
func (m *mailSpray) Purge() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.Window <= 0 {
		return
	}
	cutoff := m.now().Add(-m.cfg.Window)
	for ip, e := range m.ips {
		e.pruneFailed(cutoff)
		maps.DeleteFunc(e.trust, func(_ string, t sprayTrust) bool { return t.last.Before(cutoff) })
		if len(e.failed) == 0 && len(e.trust) == 0 {
			delete(m.ips, ip)
		}
	}
	for name, n := range m.names {
		maps.DeleteFunc(n.networks, func(_ string, ts time.Time) bool { return ts.Before(cutoff) })
		if len(n.networks) == 0 {
			delete(m.names, name)
		}
	}
}

// Size returns the number of tracked IPs.
func (m *mailSpray) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.ips)
}

// sprayNetworkKey is the network a source counts as for corroboration: the
// IPv4 /16 (IPv4-mapped included) or the IPv6 /32. "" if ip does not parse.
func sprayNetworkKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.Unmap().WithZone("")
	bits := 32
	if a.Is4() {
		bits = 16
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

// The helpers below run with m.mu held.

func (m *mailSpray) touch(ip string, now time.Time) *sprayIP {
	e := m.ips[ip]
	if e == nil {
		e = &sprayIP{}
		m.ips[ip] = e
	}
	e.lastSeen = now
	return e
}

// recordFailure notes one failure on name. It returns false when the name is
// new and the IP already holds maxSprayNamesPerIP live names.
func (e *sprayIP) recordFailure(name string, exist mailboxExistence, now time.Time, window time.Duration) bool {
	f, ok := e.failed[name]
	if !ok && len(e.failed) >= maxSprayNamesPerIP {
		e.pruneFailed(now.Add(-window))
		if len(e.failed) >= maxSprayNamesPerIP {
			return false
		}
	}
	if !ok || now.Sub(f.last) > window {
		f = sprayFailure{exist: exist}
	} else {
		f.exist = foldObservedExistence(f.exist, exist)
	}
	f.count++
	f.last = now
	if e.failed == nil {
		e.failed = make(map[string]sprayFailure)
	}
	e.failed[name] = f
	return true
}

// foldObservedExistence merges what separate failures say about one name
// over time. Unlike combineMailboxExistence, the fold for one request across
// a passdb chain, unknown here means no information (an IMAP failure carries
// none), so a missing answer outweighs it. One exists answer outweighs all.
func foldObservedExistence(a, b mailboxExistence) mailboxExistence {
	switch {
	case a == mailboxExists || b == mailboxExists:
		return mailboxExists
	case a == mailboxMissing || b == mailboxMissing:
		return mailboxMissing
	}
	return mailboxExistenceUnknown
}

func (e *sprayIP) pruneFailed(cutoff time.Time) {
	maps.DeleteFunc(e.failed, func(_ string, f sprayFailure) bool { return f.last.Before(cutoff) })
}

func (e *sprayIP) failuresInWindow(name string, now time.Time, window time.Duration) int {
	f, ok := e.failed[name]
	if !ok || now.Sub(f.last) > window {
		return 0
	}
	return f.count
}

// recordTrust records a clean login on name and reports whether a live trust
// record already existed. A record idle for a whole window starts over.
func (m *mailSpray) recordTrust(e *sprayIP, name string, now time.Time) bool {
	t, ok := e.trust[name]
	live := ok && now.Sub(t.last) <= m.cfg.Window
	if !live {
		if !ok && len(e.trust) >= maxSprayTrustPerIP {
			oldest := ""
			for n, tr := range e.trust {
				if oldest == "" || tr.last.Before(e.trust[oldest].last) {
					oldest = n
				}
			}
			delete(e.trust, oldest)
		}
		t.first = now
	}
	t.last = now
	if e.trust == nil {
		e.trust = make(map[string]sprayTrust)
	}
	e.trust[name] = t
	return live
}

// agedTrust is trust that is still live and older than TrustAge (4b).
func (m *mailSpray) agedTrust(e *sprayIP, name string, now time.Time) bool {
	t, ok := e.trust[name]
	return ok && now.Sub(t.last) <= m.cfg.Window && now.Sub(t.first) >= m.cfg.TrustAge
}

func (m *mailSpray) agedTrustCount(e *sprayIP, except string, now time.Time) int {
	n := 0
	for name := range e.trust {
		if name != except && m.agedTrust(e, name, now) {
			n++
		}
	}
	return n
}

// untrusted returns the IP's failed names in the window without aged trust,
// sorted.
func (m *mailSpray) untrusted(e *sprayIP, now time.Time) []string {
	var out []string
	for name, f := range e.failed {
		if now.Sub(f.last) <= m.cfg.Window && !m.agedTrust(e, name, now) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func (m *mailSpray) verdict(e *sprayIP, rule sprayRule, block bool, mailbox string, untrusted []string, now time.Time) *sprayVerdict {
	v := &sprayVerdict{Rule: rule, Block: block, Mailbox: mailbox, Targets: untrusted}
	if len(untrusted) > maxMailTargetsListed {
		v.Targets = untrusted[:maxMailTargetsListed:maxMailTargetsListed]
		v.Extra = len(untrusted) - maxMailTargetsListed
	}
	e.verdictAt = now
	return v
}

// corroborate notes that ip's network tried the missing name and returns how
// many networks tried it within the window.
func (m *mailSpray) corroborate(name, ip string, now time.Time) int {
	key := sprayNetworkKey(ip)
	n := m.names[name]
	if key == "" {
		return m.networkCount(n, now)
	}
	if n == nil {
		n = &sprayName{networks: make(map[string]time.Time)}
		m.names[name] = n
	}
	if _, ok := n.networks[key]; !ok && len(n.networks) >= maxSprayNetworksPerName {
		oldest := ""
		for k, ts := range n.networks {
			if oldest == "" || ts.Before(n.networks[oldest]) {
				oldest = k
			}
		}
		delete(n.networks, oldest)
	}
	n.networks[key] = now
	n.last = now
	m.evictNames(name, now)
	return m.networkCount(n, now)
}

func (m *mailSpray) networkCount(n *sprayName, now time.Time) int {
	if n == nil {
		return 0
	}
	c := 0
	for _, ts := range n.networks {
		if now.Sub(ts) <= m.cfg.Window {
			c++
		}
	}
	return c
}

// corroboratedMissing reports whether name is missing for this IP and tried
// from enough networks for rule 2.
func (m *mailSpray) corroboratedMissing(e *sprayIP, name string, now time.Time) bool {
	return m.cfg.MissingNetworks > 0 && e.failed[name].exist == mailboxMissing &&
		m.networkCount(m.names[name], now) >= m.cfg.MissingNetworks
}

// Eviction ranks, lowest dropped first. Attacker-chosen IPs and names come
// cheap, so one-shot entries go before multi-failure evidence, IPs that drew
// a verdict, and IPs holding trust.
const (
	sprayRankOneShot = iota
	sprayRankRepeat
	sprayRankVerdict
	sprayRankTrust
)

func (m *mailSpray) ipRank(e *sprayIP, now time.Time) int {
	if len(e.trust) > 0 {
		return sprayRankTrust
	}
	if !e.verdictAt.IsZero() && now.Sub(e.verdictAt) <= m.cfg.Window {
		return sprayRankVerdict
	}
	n := 0
	for _, f := range e.failed {
		if now.Sub(f.last) <= m.cfg.Window {
			n += f.count
		}
	}
	if n >= 2 {
		return sprayRankRepeat
	}
	return sprayRankOneShot
}

func (m *mailSpray) evictIPs(keep string, now time.Time) {
	sprayEvict(m.ips, m.cfg.MaxIPs, keep,
		func(e *sprayIP) int { return m.ipRank(e, now) },
		func(e *sprayIP) time.Time { return e.lastSeen })
}

// evictNames keeps names already over the rule 2 bar ahead of a flood of
// invented ones.
func (m *mailSpray) evictNames(keep string, now time.Time) {
	sprayEvict(m.names, maxSprayCorroborationNames, keep,
		func(n *sprayName) int {
			if m.cfg.MissingNetworks > 0 && m.networkCount(n, now) >= m.cfg.MissingNetworks {
				return sprayRankRepeat
			}
			return sprayRankOneShot
		},
		func(n *sprayName) time.Time { return n.last })
}

type sprayVictim struct {
	key  string
	rank int
	seen time.Time
}

// sprayEvict trims m to 95% of limit when it is over limit, dropping the
// lowest rank first and the least recently seen within a rank. keep is the
// entry the caller just wrote and is never dropped. The 95% target spaces
// out the sorts under a flood.
func sprayEvict[V any](m map[string]V, limit int, keep string, rank func(V) int, seen func(V) time.Time) {
	if len(m) <= limit {
		return
	}
	victims := make([]sprayVictim, 0, len(m))
	for k, v := range m {
		if k != keep {
			victims = append(victims, sprayVictim{k, rank(v), seen(v)})
		}
	}
	slices.SortFunc(victims, func(a, b sprayVictim) int {
		if c := cmp.Compare(a.rank, b.rank); c != 0 {
			return c
		}
		return a.seen.Compare(b.seen)
	})
	target := limit * 95 / 100
	for _, v := range victims {
		if len(m) <= target {
			break
		}
		delete(m, v.key)
	}
}
