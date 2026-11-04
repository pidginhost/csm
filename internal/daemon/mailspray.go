package daemon

import (
	"cmp"
	"iter"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/store"
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

// sprayMinTrackedPerTracker is the validated floor of each tracker's
// max_tracked, used when a config that skipped defaults leaves one at 0.
const sprayMinTrackedPerTracker = 1000

// sprayConfigFromThresholds derives the spray settings from the thresholds
// block. Trust ages and verdicts repeat on the slower of the two trackers,
// and the IP cap is their combined capacity.
func sprayConfigFromThresholds(cfg *config.Config) sprayConfig {
	th := &cfg.Thresholds
	maxTracked := func(n int) int {
		if n <= 0 {
			return sprayMinTrackedPerTracker
		}
		return n
	}
	return sprayConfig{
		Mode:             parseSprayMode(th.MailSprayMode),
		Window:           time.Duration(th.MailSprayWindowMin) * time.Minute,
		BreadthMailboxes: th.MailSprayBreadthMailboxes,
		MissingNetworks:  th.MailSprayMissingNetworks,
		TrustAge:         time.Duration(max(th.SMTPBruteForceWindowMin, th.MailBruteForceWindowMin)) * time.Minute,
		Suppression:      time.Duration(max(th.SMTPBruteForceSuppressMin, th.MailBruteForceSuppressMin)) * time.Minute,
		MaxIPs:           maxTracked(th.SMTPBruteForceMaxTracked) + maxTracked(th.MailBruteForceMaxTracked),
	}
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

// sprayStaleSpread is how long before a login the failures on its mailbox
// must have started for the stale password advisory (4d). A user who
// mistypes and retries within the hour is not news.
const sprayStaleSpread = time.Hour

const (
	maxSprayNamesPerIP         = 16
	maxSprayTrustPerIP         = mailGoodSourceMaxAccountsPerIP
	maxSprayTrustIPsPerMailbox = 64
	maxSprayCorroborationNames = 20000
	maxSprayNetworksPerName    = 50
)

type sprayFailure struct {
	first time.Time // first failure since the name was last idle for a whole window
	last  time.Time
	count int // failures since first
	exist mailboxExistence
}

type sprayTrust struct{ first, last time.Time }

type sprayTrustKey struct{ ip, mailbox string }

// sprayIP is the failure evidence of one evidence key (sprayEvidenceKey).
type sprayIP struct {
	failed        map[string]sprayFailure
	weakAlerted   map[string]time.Time   // success mailbox to its last weak_compromise
	revoked       map[string]time.Time   // known cracks cannot earn trust during the window
	sources       map[string]spraySource // verdict cadence by address
	untracked     time.Time              // latest untrusted failure refused at the name cap
	verdictAt     time.Time
	observedAt    time.Time // last observe mode block verdict
	observedNames int       // untrusted names it listed
	lastSeen      time.Time
}

// spraySource is one address's verdict cadence. Blocks target the address,
// so an IPv6 /64 shares evidence but each of its addresses draws and is
// suppressed from verdicts on its own.
type spraySource struct{ blockUntil, compromiseUntil time.Time }

func (s spraySource) lapse() time.Time {
	if s.blockUntil.After(s.compromiseUntil) {
		return s.blockUntil
	}
	return s.compromiseUntil
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
//
// Evidence and trust are two pools, each capped at MaxIPs entries and
// evicted on its own, so a flood of failures cannot evict trust and a flood
// of clean logins (anyone can own a mailbox on a shared host) cannot evict
// evidence. One IP may sit in both. Evidence is kept per IPv4 address and
// per IPv6 /64; trust is kept per address.
type mailSpray struct {
	mu    sync.Mutex
	cfg   sprayConfig
	now   func() time.Time
	ips   map[string]*sprayIP // evidence pool, by sprayEvidenceKey
	names map[string]*sprayName

	trust          map[sprayTrustKey]sprayTrust   // trust pool
	trustByIP      map[string]map[string]struct{} // ip to its trusted mailboxes
	trustByMailbox map[string]map[string]struct{} // mailbox to the IPs it trusts
	trustByKey     map[string]map[string]struct{} // evidence key to its IPs holding trust

	// Eviction floors of the evidence and corroboration pools, set when a
	// full pool's batch eviction stops before entries over a bar (see
	// sprayEvict). Ranks change with time and config, so Purge, SetConfig
	// and Load clear them.
	ipFloor, nameFloor int

	// Persistence bookkeeping, so a save writes only what changed. full
	// makes the next save rewrite the whole bucket instead: at start, after
	// Load or a reset, and if the bookkeeping outgrows its bound.
	full         bool
	ipChanges    sprayChanges // evidence IPs
	trustChanges sprayChanges // trust IPs
	nameChanges  sprayChanges // corroboration names
}

// sprayChanges tracks one kind of saved key: those changed since the last
// save and those the bucket holds.
type sprayChanges struct{ dirty, saved map[string]struct{} }

func newSprayChanges() sprayChanges {
	return sprayChanges{dirty: make(map[string]struct{}), saved: make(map[string]struct{})}
}

func newMailSpray(cfg sprayConfig, now func() time.Time) *mailSpray {
	return &mailSpray{
		cfg:            cfg,
		now:            now,
		ips:            make(map[string]*sprayIP),
		names:          make(map[string]*sprayName),
		trust:          make(map[sprayTrustKey]sprayTrust),
		trustByIP:      make(map[string]map[string]struct{}),
		trustByMailbox: make(map[string]map[string]struct{}),
		trustByKey:     make(map[string]map[string]struct{}),
		full:           true,
		ipChanges:      newSprayChanges(),
		trustChanges:   newSprayChanges(),
		nameChanges:    newSprayChanges(),
	}
}

// SetConfig applies a reloaded config. Turning the component off drops its
// memory.
func (m *mailSpray) SetConfig(cfg sprayConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
	m.ipFloor, m.nameFloor = 0, 0
	if cfg.Window <= 0 {
		clear(m.ips)
		clear(m.names)
		clear(m.trust)
		clear(m.trustByIP)
		clear(m.trustByMailbox)
		clear(m.trustByKey)
		m.resetChanges()
		return
	}
	m.evictIPs("", m.now())
	m.evictTrust(sprayTrustKey{})
}

// Enabled reports whether the component keeps memory: with no window it
// records nothing, so its verdicts say nothing about a login.
func (m *mailSpray) Enabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Window > 0
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
	key := sprayEvidenceKey(ip)
	e := m.touch(key, now)
	// Rank the current IP after its verdict, including it as an eviction
	// candidate so fresh noise cannot displace stronger evidence.
	defer m.evictIPs(key, now)
	stored := m.recordFailure(e, key, mailbox, exist, now)
	networks := 0
	if exist == mailboxMissing {
		networks = m.corroborate(mailbox, ip, now)
	}
	src := e.sources[ip]
	if m.cfg.Mode == sprayOff || now.Before(src.blockUntil) {
		return nil
	}

	untrusted := m.untrusted(e, key, now)
	missing := m.cfg.MissingNetworks > 0 && exist == mailboxMissing &&
		networks >= m.cfg.MissingNetworks && m.keyTrustCount(key, "", 1, now) == 0
	if !missing && (m.cfg.BreadthMailboxes <= 0 || !m.breadth(key, mailbox, stored, untrusted, now)) {
		return nil
	}
	// Observe mode blocks nothing, so an IP over the bar keeps failing.
	if m.cfg.Mode == sprayObserve && !e.noteObserved(len(untrusted), now, m.cfg.Window) {
		return nil
	}
	src.blockUntil = now.Add(m.cfg.Suppression)
	e.setSource(ip, src)
	if missing {
		v := m.verdict(e, sprayRuleMissingMailbox, true, mailbox, untrusted, now)
		v.Networks = networks
		return v
	}
	return m.verdict(e, sprayRuleBreadth, true, "", untrusted, now)
}

// breadth reports whether the key's untrusted names reach the rule 3 bar. A
// name refused at the per-IP cap still counts, and a full IP satisfies any
// bar above the cap.
func (m *mailSpray) breadth(key, mailbox string, stored bool, untrusted []string, now time.Time) bool {
	n := len(untrusted)
	if !stored && !m.excused(key, mailbox, now) {
		n++
	}
	return n >= min(m.cfg.BreadthMailboxes, maxSprayNamesPerIP)
}

// Success records a successful login on a normalised mailbox. clean is true
// when the login earned or refreshed trust. A login that follows failures on
// other untrusted mailboxes earns nothing and may be a compromise. A login
// never adds to the evidence pool.
func (m *mailSpray) Success(ip, mailbox string) (clean bool, v *sprayVerdict) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.Window <= 0 || mailbox == "" {
		return false, nil
	}
	now := m.now()
	k := sprayTrustKey{ip, mailbox}
	key := sprayEvidenceKey(ip)
	e := m.ips[key]
	if m.agedTrust(ip, mailbox, now) || m.trustPredatesFailures(e, k, key, now) {
		t := m.trust[k]
		t.last = now
		m.trust[k] = t
		m.markTrust(ip)
		return true, nil
	}
	if e != nil {
		m.markIP(key)
	}

	var untrusted []string
	if e != nil {
		untrusted = m.untrusted(e, key, now)
	}
	others := slices.DeleteFunc(slices.Clone(untrusted), func(n string) bool { return n == mailbox })
	if len(others) == 0 && (e == nil || !e.hasUntracked(now, m.cfg.Window)) {
		if e != nil {
			if at, ok := e.revoked[mailbox]; ok && now.Sub(at) <= m.cfg.Window {
				return false, nil
			}
		}
		hadTrust := m.recordTrust(k, now)
		// 4d fires once per trust relationship; later logins while the new
		// trust ages are the same user.
		if m.cfg.Mode == sprayOff || hadTrust || e == nil || !e.staleFailures(mailbox, now, m.cfg.Window) {
			return true, nil
		}
		return true, m.verdict(e, sprayRuleSingleMailboxSuccess, false, mailbox, untrusted, now)
	}

	src := e.sources[ip]
	if m.cfg.Mode == sprayOff || now.Before(src.compromiseUntil) {
		return false, nil
	}
	rule, block := sprayRuleWeakCompromise, false
	if slices.ContainsFunc(others, func(n string) bool { return m.corroboratedMissing(e, n, now) }) {
		rule = sprayRuleCompromise
		block = m.keyTrustCount(key, mailbox, mailEstablishedSourceAccounts, now) < mailEstablishedSourceAccounts
	} else if !e.noteWeakAlert(mailbox, now, m.cfg.Window) {
		// A polling client logs in every few minutes: the advisory fires
		// once per mailbox per window, not once per suppression period.
		return false, nil
	}
	src.compromiseUntil = now.Add(m.cfg.Suppression)
	e.setSource(ip, src)
	return false, m.verdict(e, rule, block, mailbox, untrusted, now)
}

// trustPredatesFailures reports whether k holds live trust that began
// before every untrusted failure on another mailbox: a clean login those
// failures came after, so they cannot taint it.
func (m *mailSpray) trustPredatesFailures(e *sprayIP, k sprayTrustKey, key string, now time.Time) bool {
	t, ok := m.trust[k]
	if !ok || now.Sub(t.last) > m.cfg.Window {
		return false
	}
	if e == nil {
		return true
	}
	// A failure refused at the name cap has no first time to compare.
	if e.hasUntracked(now, m.cfg.Window) {
		return false
	}
	for name, f := range e.failed {
		if name != k.mailbox && now.Sub(f.last) <= m.cfg.Window && !f.first.After(t.first) && !m.excused(key, name, now) {
			return false
		}
	}
	return true
}

// RevokeTrust drops the IP's trust on a normalised mailbox, for a login the
// caller knows was a guessed password. Remember the crack for the evidence
// window so another login, on either protocol, cannot immediately restore it.
func (m *mailSpray) RevokeTrust(ip, mailbox string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropTrust(sprayTrustKey{ip, mailbox})
	if m.cfg.Window <= 0 {
		return
	}
	now := m.now()
	key := sprayEvidenceKey(ip)
	m.touch(key, now).noteRevoked(mailbox, now, m.cfg.Window)
	m.evictIPs(key, now)
}

// ForgetRecentFailures drops the IP's failures since "since": an outage
// starts before it is detected, and its failures are no evidence. A name
// that also failed before keeps only its first failure. Trust, verdicts
// and corroboration stay.
func (m *mailSpray) ForgetRecentFailures(ip string, since time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := sprayEvidenceKey(ip)
	e := m.ips[key]
	if e == nil {
		return
	}
	changed := false
	for name, f := range e.failed {
		switch {
		case f.last.Before(since):
			continue
		case f.first.Before(since):
			f.last, f.count = f.first, 1
			e.failed[name] = f
		default:
			delete(e.failed, name)
		}
		changed = true
	}
	if changed {
		m.markIP(key)
	}
}

// TrustedAll reports whether the IP holds aged trust on every one of the
// normalised mailboxes. An empty list is not trusted.
func (m *mailSpray) TrustedAll(ip string, mailboxes []string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.Window <= 0 || len(mailboxes) == 0 {
		return false
	}
	now := m.now()
	for _, mb := range mailboxes {
		if !m.agedTrust(ip, mb, now) {
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
	m.ipFloor, m.nameFloor = 0, 0
	cutoff := m.now().Add(-m.cfg.Window)
	for ip, e := range m.ips {
		records := len(e.failed) + len(e.weakAlerted) + len(e.revoked)
		e.pruneFailed(cutoff)
		maps.DeleteFunc(e.weakAlerted, func(_ string, at time.Time) bool { return at.Before(cutoff) })
		maps.DeleteFunc(e.revoked, func(_ string, at time.Time) bool { return at.Before(cutoff) })
		if !e.untracked.IsZero() && e.untracked.Before(cutoff) {
			e.untracked = time.Time{}
			records++
		}
		changed := records != len(e.failed)+len(e.weakAlerted)+len(e.revoked)
		// ForgetRecentFailures can leave an entry with no records, so an
		// entry dropped here may not have changed in this pass.
		if len(e.failed) == 0 && e.untracked.IsZero() && len(e.weakAlerted) == 0 && len(e.revoked) == 0 {
			delete(m.ips, ip)
			changed = true
		}
		if changed {
			m.markIP(ip)
		}
	}
	for k, t := range m.trust {
		if t.last.Before(cutoff) {
			m.dropTrust(k)
		}
	}
	for name, n := range m.names {
		networks := len(n.networks)
		maps.DeleteFunc(n.networks, func(_ string, ts time.Time) bool { return ts.Before(cutoff) })
		if len(n.networks) == 0 {
			delete(m.names, name)
		}
		if len(n.networks) != networks {
			m.markName(name)
		}
	}
}

// Size returns the number of IPs in the evidence pool.
func (m *mailSpray) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.ips)
}

// TrustSize returns the number of (IP, mailbox) records in the trust pool.
func (m *mailSpray) TrustSize() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.trust)
}

// Export returns a copy of the whole memory.
func (m *mailSpray) Export() store.MailSprayState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exportAll()
}

// ExportChanges returns what changed since the last save and starts a new
// change set. full reports that the save must replace the whole bucket; Put
// then holds the whole memory. Only changed entries are copied under the
// lock otherwise. A caller whose save fails hands the delta to RetryChanges.
func (m *mailSpray) ExportChanges() (d store.MailSprayDelta, full bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.full {
		m.full = false
		m.ipChanges.saveAll(maps.Keys(m.ips))
		m.trustChanges.saveAll(maps.Keys(m.trustByIP))
		m.nameChanges.saveAll(maps.Keys(m.names))
		return store.MailSprayDelta{Put: m.exportAll()}, true
	}
	d.Put = store.MailSprayState{
		IPs:      make(map[string]store.MailSprayIP, len(m.ipChanges.dirty)),
		Trust:    make(map[string]map[string]store.GoodSourcePair, len(m.trustChanges.dirty)),
		Networks: make(map[string]map[string]time.Time, len(m.nameChanges.dirty)),
	}
	d.DeleteIPs = m.ipChanges.export(func(ip string) bool {
		e := m.ips[ip]
		if e != nil {
			d.Put.IPs[ip] = exportSprayIP(e)
		}
		return e != nil
	})
	d.DeleteTrust = m.trustChanges.export(func(ip string) bool {
		if len(m.trustByIP[ip]) == 0 {
			return false
		}
		d.Put.Trust[ip] = m.exportTrust(ip)
		return true
	})
	d.DeleteNames = m.nameChanges.export(func(name string) bool {
		n := m.names[name]
		if n != nil {
			d.Put.Networks[name] = maps.Clone(n.networks)
		}
		return n != nil
	})
	return d, false
}

// RetryChanges takes back the changes of a failed save, so the next save
// writes those keys again with their values at that time.
func (m *mailSpray) RetryChanges(d store.MailSprayDelta, full bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.full {
		return
	}
	if full {
		m.resetChanges()
		return
	}
	for _, k := range []struct {
		changes sprayChanges
		puts    iter.Seq[string]
		deletes []string
		mark    func(string)
	}{
		{m.ipChanges, maps.Keys(d.Put.IPs), d.DeleteIPs, m.markIP},
		{m.trustChanges, maps.Keys(d.Put.Trust), d.DeleteTrust, m.markTrust},
		{m.nameChanges, maps.Keys(d.Put.Networks), d.DeleteNames, m.markName},
	} {
		// The deletes did not happen: the bucket still holds those keys.
		for _, key := range k.deletes {
			k.changes.saved[key] = struct{}{}
			k.mark(key)
			if m.full {
				return
			}
		}
		for key := range k.puts {
			k.mark(key)
			if m.full {
				return
			}
		}
	}
}

func (m *mailSpray) markIP(ip string) {
	m.mark(m.ipChanges, ip, m.ips[ip] != nil, m.cfg.MaxIPs)
}

func (m *mailSpray) markTrust(ip string) {
	m.mark(m.trustChanges, ip, len(m.trustByIP[ip]) > 0, m.cfg.MaxIPs)
}

func (m *mailSpray) markName(name string) {
	m.mark(m.nameChanges, name, m.names[name] != nil, maxSprayCorroborationNames)
}

// mark records that key changed; live says whether memory still holds it.
// A key gone from memory that the bucket never held needs no delete, so it
// leaves the change set: attacker churn of short-lived entries cannot grow
// the set or force a rewrite of idle entries. The sets stay within the pool
// plus the bucket while saves succeed; saves that keep failing can grow
// them, so past twice the pool the next save rewrites the bucket instead.
func (m *mailSpray) mark(c sprayChanges, key string, live bool, pool int) {
	if m.full {
		return
	}
	if _, saved := c.saved[key]; live || saved {
		c.dirty[key] = struct{}{}
	} else {
		delete(c.dirty, key)
	}
	if len(c.dirty) > 2*pool || len(c.saved) > 2*pool {
		m.resetChanges()
	}
}

func (m *mailSpray) resetChanges() {
	m.full = true
	for _, c := range []sprayChanges{m.ipChanges, m.trustChanges, m.nameChanges} {
		clear(c.dirty)
		clear(c.saved)
	}
}

// saveAll records a full save of keys.
func (c sprayChanges) saveAll(keys iter.Seq[string]) {
	clear(c.dirty)
	clear(c.saved)
	for k := range keys {
		c.saved[k] = struct{}{}
	}
}

// export hands each changed key to put, which copies a key memory still
// holds and reports whether it did. It returns the keys to delete and
// records them as saved or gone, assuming the save succeeds.
func (c sprayChanges) export(put func(string) bool) (deletes []string) {
	for k := range c.dirty {
		if put(k) {
			c.saved[k] = struct{}{}
		} else {
			deletes = append(deletes, k)
			delete(c.saved, k)
		}
	}
	clear(c.dirty)
	return deletes
}

func (m *mailSpray) exportAll() store.MailSprayState {
	st := store.MailSprayState{
		IPs:      make(map[string]store.MailSprayIP, len(m.ips)),
		Trust:    make(map[string]map[string]store.GoodSourcePair, len(m.trustByIP)),
		Networks: make(map[string]map[string]time.Time, len(m.names)),
	}
	for ip, e := range m.ips {
		st.IPs[ip] = exportSprayIP(e)
	}
	for ip := range m.trustByIP {
		st.Trust[ip] = m.exportTrust(ip)
	}
	for name, n := range m.names {
		st.Networks[name] = maps.Clone(n.networks)
	}
	return st
}

func exportSprayIP(e *sprayIP) store.MailSprayIP {
	s := store.MailSprayIP{
		Untracked:     e.untracked,
		VerdictAt:     e.verdictAt,
		ObservedAt:    e.observedAt,
		ObservedNames: e.observedNames,
		LastSeen:      e.lastSeen,
	}
	if len(e.failed) > 0 {
		s.Failed = make(map[string]store.MailSprayFailure, len(e.failed))
		for name, f := range e.failed {
			s.Failed[name] = store.MailSprayFailure{First: f.first, Last: f.last, Count: f.count, Exist: uint8(f.exist)}
		}
	}
	if len(e.weakAlerted) > 0 {
		s.WeakAlerted = maps.Clone(e.weakAlerted)
	}
	if len(e.revoked) > 0 {
		s.Revoked = maps.Clone(e.revoked)
	}
	if len(e.sources) > 0 {
		s.Sources = make(map[string]store.MailSpraySource, len(e.sources))
		for ip, src := range e.sources {
			s.Sources[ip] = store.MailSpraySource{SuppressedUntil: src.blockUntil, CompromiseUntil: src.compromiseUntil}
		}
	}
	return s
}

func (m *mailSpray) exportTrust(ip string) map[string]store.GoodSourcePair {
	out := make(map[string]store.GoodSourcePair, len(m.trustByIP[ip]))
	for mb := range m.trustByIP[ip] {
		t := m.trust[sprayTrustKey{ip, mb}]
		out[mb] = store.GoodSourcePair{First: t.first, Last: t.last}
	}
	return out
}

// Load replaces memory before log readers start. The reader visits trust before evidence
// so name eviction can prefer untrusted failures. Each pool is capped during
// replay, rather than after allocating a copy of an untrusted bucket.
func (m *mailSpray) Load(read func(func(store.MailSprayState)) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.Window <= 0 {
		return nil
	}
	now := m.now()
	cutoff := now.Add(-m.cfg.Window)
	clear(m.ips)
	clear(m.names)
	clear(m.trust)
	clear(m.trustByIP)
	clear(m.trustByMailbox)
	clear(m.trustByKey)
	// Entries load with no newcomer to check against the eviction floors,
	// so a floor a load batch sets may not hold once it is done.
	defer func() { m.ipFloor, m.nameFloor = 0, 0 }()
	// The bucket may hold entries this load dropped: rewrite it whole.
	m.resetChanges()
	return read(func(st store.MailSprayState) {
		for ip, mbs := range st.Trust {
			if !sprayValidIP(ip) {
				continue
			}
			for mb, p := range mbs {
				mb = strings.Clone(normalizeSprayMailbox(mb))
				if mb == "" || p.First.After(now) || p.Last.After(now) ||
					!validGoodSourceTimes(goodSourceTimes{First: p.First, Last: p.Last}, cutoff) {
					continue
				}
				m.loadTrust(sprayTrustKey{ip, mb}, sprayTrust{p.First, p.Last})
			}
		}
		for saved, s := range st.IPs {
			key, addr := sprayLoadEvidenceKey(saved)
			if key == "" {
				continue
			}
			if e := m.loadIP(m.ips[key], key, addr, s, cutoff, now); e != nil {
				m.ips[key] = e
				m.evictIPs("", now)
			}
		}
		for name, nets := range st.Networks {
			name = strings.Clone(normalizeSprayMailbox(name))
			if name == "" {
				continue
			}
			n := m.names[name]
			if n == nil {
				n = &sprayName{networks: make(map[string]time.Time)}
			}
			for key, at := range nets {
				// A future observation cannot corroborate a real failure now.
				if key = sprayLoadNetwork(key); key == "" || at.Before(cutoff) || at.After(now) {
					continue
				}
				sprayKeepLatest(n.networks, key, at, maxSprayNetworksPerName)
				if at.After(n.last) {
					n.last = at
				}
			}
			if len(n.networks) > 0 {
				m.names[name] = n
				m.evictNames("", now)
			}
		}
	})
}

// loadTrust keeps the most recent relationships even when disk key order
// differs from login order. Live addTrust always receives the latest login.
func (m *mailSpray) loadTrust(k sprayTrustKey, t sprayTrust) {
	if old, ok := m.trust[k]; ok {
		t.first = sprayNotAfter(t.first, old.first)
		if old.last.After(t.last) {
			t.last = old.last
		}
		m.trust[k] = t
		return
	}
	if mbs := m.trustByIP[k.ip]; len(mbs) >= maxSprayTrustPerIP {
		oldest := m.oldestTrust(mbs, func(mb string) sprayTrustKey { return sprayTrustKey{k.ip, mb} })
		if t.last.Before(m.trust[oldest].last) {
			return
		}
	}
	if ips := m.trustByMailbox[k.mailbox]; len(ips) >= maxSprayTrustIPsPerMailbox {
		oldest := m.oldestTrust(ips, func(ip string) sprayTrustKey { return sprayTrustKey{ip, k.mailbox} })
		if t.last.Before(m.trust[oldest].last) {
			return
		}
	}
	m.addTrust(k, t)
	m.evictTrust(sprayTrustKey{})
}

// loadIP merges one saved entry into the evidence of key, e (nil when there
// is none yet), and returns it, or nil when nothing is left in the window, as
// Purge would drop it. addr is the address the saved key named; a /64 key
// names none. Damaged times and counts are repaired toward weaker evidence.
func (m *mailSpray) loadIP(e *sprayIP, key, addr string, s store.MailSprayIP, cutoff, now time.Time) *sprayIP {
	if e == nil {
		e = &sprayIP{}
	}
	e.verdictAt = sprayLatest(e.verdictAt, sprayNotAfter(s.VerdictAt, now))
	e.lastSeen = sprayLatest(e.lastSeen, sprayNotAfter(s.LastSeen, now))
	if u := sprayNotAfter(s.Untracked, now); !u.Before(cutoff) {
		e.untracked = sprayLatest(e.untracked, u)
	}
	if o := sprayNotAfter(s.ObservedAt, now); !o.Before(cutoff) {
		e.observedAt = sprayLatest(e.observedAt, o)
		e.observedNames = max(e.observedNames, min(max(s.ObservedNames, 0), maxSprayNamesPerIP))
	}
	limit := now.Add(m.cfg.Suppression)
	for ip, saved := range s.Sources {
		if !sprayValidIP(ip) || sprayEvidenceKey(ip) != key {
			continue
		}
		src := e.sources[ip]
		src.blockUntil = sprayLatest(src.blockUntil, sprayNotAfter(saved.SuppressedUntil, limit))
		src.compromiseUntil = sprayLatest(src.compromiseUntil, sprayNotAfter(saved.CompromiseUntil, limit))
		e.setSource(strings.Clone(ip), src)
	}
	// Revoke before choosing failures at the name cap, including revocations
	// whose names will be represented only by the overflow marker. Live
	// revocation drops the cracking address's trust; a /64 key does not say
	// which address that was.
	for mb, at := range s.Revoked {
		mb = strings.Clone(normalizeSprayMailbox(mb))
		at = sprayNotAfter(at, now)
		if mb == "" || at.Before(cutoff) {
			continue
		}
		if addr != "" {
			m.dropTrust(sprayTrustKey{addr, mb})
		}
		if old := e.revoked[mb]; old.After(at) {
			at = old
		}
		e.noteRevoked(mb, at, m.cfg.Window)
	}
	for name, f := range s.Failed {
		last := sprayNotAfter(f.Last, now)
		if last.Before(cutoff) {
			continue
		}
		first := sprayNotAfter(f.First, now)
		if first.IsZero() || first.After(last) {
			first = last
		}
		exist := mailboxExistence(f.Exist)
		if exist > mailboxMissing {
			exist = mailboxExistenceUnknown
		}
		count := max(f.Count, 1)
		name = strings.Clone(normalizeSprayMailbox(name))
		if cur, ok := e.failed[name]; ok {
			first = sprayNotAfter(first, cur.first)
			if cur.last.After(last) {
				last = cur.last
			}
			count = max(count, cur.count)
			exist = foldObservedExistence(exist, cur.exist)
		}
		if _, ok := e.failed[name]; !ok && !m.roomForName(e, key, name, last, now) {
			continue
		}
		if e.failed == nil {
			e.failed = make(map[string]sprayFailure)
		}
		e.failed[name] = sprayFailure{first: first, last: last, count: count, exist: exist}
	}
	for mb, at := range s.WeakAlerted {
		mb = strings.Clone(normalizeSprayMailbox(mb))
		at = sprayNotAfter(at, now)
		if mb == "" || at.Before(cutoff) {
			continue
		}
		if e.weakAlerted == nil {
			e.weakAlerted = make(map[string]time.Time)
		}
		sprayKeepLatest(e.weakAlerted, mb, at, maxSprayNamesPerIP)
	}
	if len(e.failed) == 0 && e.untracked.IsZero() && len(e.weakAlerted) == 0 && len(e.revoked) == 0 {
		return nil
	}
	return e
}

// sprayKeepLatest merges a timestamp without retaining an unbounded map or
// letting an older disk entry displace newer evidence at the cap.
func sprayKeepLatest(dst map[string]time.Time, key string, at time.Time, limit int) {
	if old, ok := dst[key]; ok {
		if at.After(old) {
			dst[key] = at
		}
		return
	}
	if len(dst) >= limit {
		oldest := ""
		for k, t := range dst {
			if oldest == "" || t.Before(dst[oldest]) {
				oldest = k
			}
		}
		if at.Before(dst[oldest]) {
			return
		}
		delete(dst, oldest)
	}
	dst[key] = at
}

// sprayLoadNetwork accepts only a key sprayNetworkKey could have made.
func sprayLoadNetwork(key string) string {
	p, err := netip.ParsePrefix(key)
	if err != nil || sprayNetworkKey(p.Addr().String()) != key {
		return ""
	}
	return key
}

// sprayLoadEvidenceKey returns the evidence key a saved one belongs to and
// the address it names, if any. Older state keyed IPv6 evidence by address,
// which folds into the /64. A key that is neither an address nor a /64
// sprayEvidenceKey could have made returns "".
func sprayLoadEvidenceKey(saved string) (key, addr string) {
	if a, err := netip.ParseAddr(saved); err == nil {
		if a.Zone() != "" {
			return "", ""
		}
		return sprayEvidenceKey(saved), saved
	}
	p, err := netip.ParsePrefix(saved)
	if err != nil || sprayEvidenceKey(p.Addr().String()) != saved {
		return "", ""
	}
	return saved, ""
}

func sprayLatest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func sprayValidIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.Zone() == ""
}

func sprayNotAfter(t, limit time.Time) time.Time {
	if t.After(limit) {
		return limit
	}
	return t
}

// JSON can escape every mailbox byte into six bytes. The largest live
// record is one IP's trust map; allow its timestamps and field names too.
const maxSprayEntryBytes = max(maxSprayTrustPerIP, 3*maxSprayNamesPerIP, maxSprayNetworksPerName)*(6*maxSprayMailboxBytes+256) + 512

// mailSprayPersistTicks is how many one-minute purge ticks pass between
// saves of the spray memory, which is far larger than good-source standing.
const mailSprayPersistTicks = 5

// loadMailSpray seeds the spray memory before the log readers start.
func (d *Daemon) loadMailSpray() {
	sdb := store.Global()
	if d.mailSpray == nil || sdb == nil {
		return
	}
	if err := d.mailSpray.Load(func(visit func(store.MailSprayState)) error {
		return sdb.LoadMailSpray(maxSprayEntryBytes, visit)
	}); err != nil {
		csmlog.Warn("mail spray memory load failed", "err", err)
	}
}

// persistMailSpray saves the spray memory so a restart keeps it: the whole
// memory the first time, then only what changed.
func (d *Daemon) persistMailSpray() {
	sdb := store.Global()
	if d.mailSpray == nil || sdb == nil {
		return
	}
	delta, full := d.mailSpray.ExportChanges()
	var err error
	switch {
	case full:
		err = sdb.SaveMailSpray(delta.Put)
	case !delta.Empty():
		err = sdb.ApplyMailSprayDelta(delta)
	}
	if err != nil {
		d.mailSpray.RetryChanges(delta, full)
		csmlog.Warn("mail spray memory persistence failed", "err", err)
	}
}

// sprayEvidenceKey is the evidence entry a source's failures go to: the
// address for IPv4 (IPv4-mapped included) and the /64 for IPv6, since one
// IPv6 host can rotate through its /64. Trust and blocks stay per address.
func sprayEvidenceKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.String()
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
	m.markIP(ip)
	return e
}

// recordFailure keeps untrusted names ahead of stale-password noise. When
// no name fits, retain its time so losing the name cannot earn new trust.
func (m *mailSpray) recordFailure(e *sprayIP, key, name string, exist mailboxExistence, now time.Time) bool {
	f, ok := e.failed[name]
	if !ok && !m.roomForName(e, key, name, now, now) {
		return false
	}
	if !ok || now.Sub(f.last) > m.cfg.Window {
		f = sprayFailure{first: now, exist: exist}
	} else {
		f.exist = foldObservedExistence(f.exist, exist)
	}
	if f.count < math.MaxInt {
		f.count++
	}
	f.last = now
	if e.failed == nil {
		e.failed = make(map[string]sprayFailure)
	}
	e.failed[name] = f
	return true
}

// roomForName makes room in e.failed for a new name that failed at "at",
// dropping aged-trust names first. With no room it reports false, and an
// untrusted name leaves its time in untracked.
func (m *mailSpray) roomForName(e *sprayIP, key, name string, at, now time.Time) bool {
	if len(e.failed) < maxSprayNamesPerIP {
		return true
	}
	e.pruneFailed(now.Add(-m.cfg.Window))
	if len(e.failed) >= maxSprayNamesPerIP {
		oldest := ""
		for mb, failure := range e.failed {
			if m.excused(key, mb, now) && (oldest == "" || failure.last.Before(e.failed[oldest].last)) {
				oldest = mb
			}
		}
		if oldest != "" {
			delete(e.failed, oldest)
		}
	}
	if len(e.failed) < maxSprayNamesPerIP {
		return true
	}
	if !m.excused(key, name, now) && at.After(e.untracked) {
		e.untracked = at
	}
	return false
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

// noteWeakAlert reports whether a weak compromise advisory for mailbox may
// fire, at most once per window, and records it. The record is capped like
// failed, oldest first, and grants no trust.
func (e *sprayIP) noteWeakAlert(mailbox string, now time.Time, window time.Duration) bool {
	at, ok := e.weakAlerted[mailbox]
	if ok && now.Sub(at) <= window {
		return false
	}
	if e.weakAlerted == nil {
		e.weakAlerted = make(map[string]time.Time)
	}
	if !ok && len(e.weakAlerted) >= maxSprayNamesPerIP {
		oldest := ""
		for mb, t := range e.weakAlerted {
			if oldest == "" || t.Before(e.weakAlerted[oldest]) {
				oldest = mb
			}
		}
		delete(e.weakAlerted, oldest)
	}
	e.weakAlerted[mailbox] = now
	return true
}

// noteObserved reports whether an observe mode block verdict naming n
// untrusted mailboxes may fire, and records it: once per window, or sooner
// when n grows past what the last one listed.
func (e *sprayIP) noteObserved(n int, now time.Time, window time.Duration) bool {
	if !e.observedAt.IsZero() && now.Sub(e.observedAt) <= window && n <= e.observedNames {
		return false
	}
	e.observedAt, e.observedNames = now, n
	return true
}

// noteRevoked remembers a crack on mailbox at "at" for the window. Losing a
// cracked mailbox at the name cap must not turn its next login into clean
// evidence, so at the cap the crack goes to the overflow marker, which
// withholds new trust without disturbing other aged trust.
func (e *sprayIP) noteRevoked(mailbox string, at time.Time, window time.Duration) {
	maps.DeleteFunc(e.revoked, func(_ string, t time.Time) bool { return at.Sub(t) > window })
	if _, ok := e.revoked[mailbox]; ok || len(e.revoked) < maxSprayNamesPerIP {
		if e.revoked == nil {
			e.revoked = make(map[string]time.Time)
		}
		e.revoked[mailbox] = at
		return
	}
	if at.After(e.untracked) {
		e.untracked = at
	}
}

// setSource records ip's verdict cadence. At the cap the record that lapses
// first goes; losing a live one only lets an address already reported draw
// another verdict.
func (e *sprayIP) setSource(ip string, src spraySource) {
	if _, ok := e.sources[ip]; !ok && len(e.sources) >= maxSprayNamesPerIP {
		first := ""
		for a, s := range e.sources {
			if first == "" || s.lapse().Before(e.sources[first].lapse()) {
				first = a
			}
		}
		delete(e.sources, first)
	}
	if e.sources == nil {
		e.sources = make(map[string]spraySource)
	}
	e.sources[ip] = src
}

func (e *sprayIP) hasUntracked(now time.Time, window time.Duration) bool {
	return !e.untracked.IsZero() && now.Sub(e.untracked) <= window
}

// staleFailures reports whether name failed at least twice in the window,
// the first time at least sprayStaleSpread ago: a saved password gone
// stale, not a typo (4d).
func (e *sprayIP) staleFailures(name string, now time.Time, window time.Duration) bool {
	f, ok := e.failed[name]
	return ok && now.Sub(f.last) <= window && f.count >= 2 && now.Sub(f.first) >= sprayStaleSpread
}

// recordTrust records a clean login and reports whether a live trust record
// already existed. A record idle for a whole window starts over.
func (m *mailSpray) recordTrust(k sprayTrustKey, now time.Time) bool {
	t, ok := m.trust[k]
	live := ok && now.Sub(t.last) <= m.cfg.Window
	if !live {
		t.first = now
	}
	t.last = now
	if ok {
		m.trust[k] = t
		m.markTrust(k.ip)
	} else {
		m.addTrust(k, t)
	}
	m.evictTrust(k)
	return live
}

// addTrust stores a new record. It makes room in its IP's and its mailbox's
// share first, so one owned mailbox cannot fill the pool from fresh IPs.
func (m *mailSpray) addTrust(k sprayTrustKey, t sprayTrust) {
	if mbs := m.trustByIP[k.ip]; len(mbs) >= maxSprayTrustPerIP {
		m.dropTrust(m.oldestTrust(mbs, func(mb string) sprayTrustKey { return sprayTrustKey{k.ip, mb} }))
	}
	if ips := m.trustByMailbox[k.mailbox]; len(ips) >= maxSprayTrustIPsPerMailbox {
		m.dropTrust(m.oldestTrust(ips, func(ip string) sprayTrustKey { return sprayTrustKey{ip, k.mailbox} }))
	}
	setAdd(m.trustByIP, k.ip, k.mailbox)
	setAdd(m.trustByMailbox, k.mailbox, k.ip)
	setAdd(m.trustByKey, sprayEvidenceKey(k.ip), k.ip)
	m.trust[k] = t
	m.markTrust(k.ip)
}

func (m *mailSpray) dropTrust(k sprayTrustKey) {
	_, ok := m.trust[k]
	delete(m.trust, k)
	setDel(m.trustByIP, k.ip, k.mailbox)
	setDel(m.trustByMailbox, k.mailbox, k.ip)
	if ok && len(m.trustByIP[k.ip]) == 0 {
		setDel(m.trustByKey, sprayEvidenceKey(k.ip), k.ip)
	}
	if ok {
		m.markTrust(k.ip)
	}
}

// oldestTrust returns the record with the oldest last success among set.
func (m *mailSpray) oldestTrust(set map[string]struct{}, key func(string) sprayTrustKey) sprayTrustKey {
	var oldest sprayTrustKey
	found := false
	for s := range set {
		k := key(s)
		if !found || m.trust[k].last.Before(m.trust[oldest].last) {
			oldest, found = k, true
		}
	}
	return oldest
}

func setAdd(idx map[string]map[string]struct{}, k, v string) {
	if idx[k] == nil {
		idx[k] = make(map[string]struct{})
	}
	idx[k][v] = struct{}{}
}

func setDel(idx map[string]map[string]struct{}, k, v string) {
	delete(idx[k], v)
	if len(idx[k]) == 0 {
		delete(idx, k)
	}
}

// agedTrust is trust that is still live and older than TrustAge (4b).
func (m *mailSpray) agedTrust(ip, mailbox string, now time.Time) bool {
	t, ok := m.trust[sprayTrustKey{ip, mailbox}]
	return ok && now.Sub(t.last) <= m.cfg.Window && now.Sub(t.first) >= m.cfg.TrustAge
}

// excused reports whether an address of evidence key holds aged trust on
// mailbox. Trust is earned per address, but an IPv6 /64 is one network's
// evidence, so trust any of its addresses earned excuses failures on that
// mailbox for all of them. An IPv4 key holds only its own address.
func (m *mailSpray) excused(key, mailbox string, now time.Time) bool {
	a, b := m.trustByKey[key], m.trustByMailbox[mailbox]
	if len(a) > len(b) {
		a, b = b, a
	}
	for ip := range a {
		if _, ok := b[ip]; ok && m.agedTrust(ip, mailbox, now) {
			return true
		}
	}
	return false
}

// keyTrustCount counts, up to limit, the mailboxes other than except that
// addresses of evidence key hold aged trust on. The scan is bounded by the
// trust pool and stops at limit.
func (m *mailSpray) keyTrustCount(key, except string, limit int, now time.Time) int {
	seen := make(map[string]struct{}, limit)
	for ip := range m.trustByKey[key] {
		for mb := range m.trustByIP[ip] {
			if mb == except || !m.agedTrust(ip, mb, now) {
				continue
			}
			seen[mb] = struct{}{}
			if len(seen) >= limit {
				return len(seen)
			}
		}
	}
	return len(seen)
}

// untrusted returns the key's failed names in the window that no address of
// the key holds aged trust on, sorted.
func (m *mailSpray) untrusted(e *sprayIP, key string, now time.Time) []string {
	var out []string
	for name, f := range e.failed {
		if now.Sub(f.last) <= m.cfg.Window && !m.excused(key, name, now) {
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
	n.note(key, now)
	m.markName(name)
	m.evictNames(name, now)
	return m.networkCount(n, now)
}

// note records that network key tried the name at "at", dropping the oldest
// network at the cap.
func (n *sprayName) note(key string, at time.Time) {
	if _, ok := n.networks[key]; !ok && len(n.networks) >= maxSprayNetworksPerName {
		oldest := ""
		for k, ts := range n.networks {
			if oldest == "" || ts.Before(n.networks[oldest]) {
				oldest = k
			}
		}
		delete(n.networks, oldest)
	}
	n.networks[key] = at
	if at.After(n.last) {
		n.last = at
	}
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

// Evidence eviction ranks, lowest dropped first. Attacker-chosen IPs and
// names come cheap, so one-shot entries go before multi-failure evidence and
// IPs that drew a verdict.
const (
	sprayRankOneShot = iota
	sprayRankRepeat
	sprayRankVerdict
)

func (m *mailSpray) ipRank(e *sprayIP, now time.Time) int {
	if !e.verdictAt.IsZero() && now.Sub(e.verdictAt) <= m.cfg.Window {
		return sprayRankVerdict
	}
	for _, at := range e.revoked {
		if now.Sub(at) <= m.cfg.Window {
			return sprayRankVerdict
		}
	}
	if e.hasUntracked(now, m.cfg.Window) {
		return sprayRankRepeat
	}
	n := 0
	for _, f := range e.failed {
		if now.Sub(f.last) <= m.cfg.Window {
			if f.count >= 2-n {
				return sprayRankRepeat
			}
			n += f.count
		}
	}
	return sprayRankOneShot
}

func (m *mailSpray) evictIPs(keep string, now time.Time) {
	sprayEvict(m.ips, m.cfg.MaxIPs, keep, &m.ipFloor,
		func(e *sprayIP) int { return m.ipRank(e, now) },
		func(e *sprayIP) time.Time { return e.lastSeen },
		func(ip string) {
			delete(m.ips, ip)
			m.markIP(ip)
		})
}

// evictTrust drops the oldest last success first: trust is earned with a real
// password, so recency is all that tells records apart.
func (m *mailSpray) evictTrust(keep sprayTrustKey) {
	sprayEvict(m.trust, m.cfg.MaxIPs, keep, new(int),
		func(sprayTrust) int { return 0 },
		func(t sprayTrust) time.Time { return t.last },
		m.dropTrust)
}

// evictNames keeps names already over the rule 2 bar ahead of a flood of
// invented ones. Such a name ranks with verdict evidence.
func (m *mailSpray) evictNames(keep string, now time.Time) {
	sprayEvict(m.names, maxSprayCorroborationNames, keep, &m.nameFloor,
		func(n *sprayName) int {
			if m.cfg.MissingNetworks > 0 && m.networkCount(n, now) >= m.cfg.MissingNetworks {
				return sprayRankVerdict
			}
			return sprayRankOneShot
		},
		func(n *sprayName) time.Time { return n.last },
		func(name string) {
			delete(m.names, name)
			m.markName(name)
		})
}

type sprayVictim[K comparable] struct {
	key  K
	rank int
	seen time.Time
}

// sprayEvict drops the lowest rank first, then the least recently seen.
// keep wins ties within its rank, but cannot displace a higher rank. Once
// within limit, batch removal goes on to 95% of it, through one-shot and
// multi-failure entries alike, but stops before entries over a bar
// (sprayRankVerdict): spare capacity must not cost them. It then records
// their rank in *floor, as every entry left ranks at least that high.
// While that holds, a newcomer ranked below the floor is the one entry a
// sort would drop, so it is dropped without sorting the pool. One admitted
// into spare room instead ends the promise. drop also updates indexes.
func sprayEvict[K comparable, V any](m map[K]V, limit int, keep K, floor *int, rank func(V) int, seen func(V) time.Time, drop func(K)) {
	if v, ok := m[keep]; ok && *floor > 0 && rank(v) < *floor {
		if len(m) <= limit {
			*floor = 0
			return
		}
		drop(keep)
	}
	if len(m) <= limit {
		return
	}
	victims := make([]sprayVictim[K], 0, len(m))
	for k, v := range m {
		victims = append(victims, sprayVictim[K]{k, rank(v), seen(v)})
	}
	slices.SortFunc(victims, func(a, b sprayVictim[K]) int {
		if c := cmp.Compare(a.rank, b.rank); c != 0 {
			return c
		}
		if c := a.seen.Compare(b.seen); c != 0 {
			return c
		}
		if a.key == keep && b.key != keep {
			return 1
		}
		if b.key == keep && a.key != keep {
			return -1
		}
		return 0
	})
	target := limit * 95 / 100
	if limit > 0 {
		target = max(1, target)
	}
	lastRank := victims[0].rank
	for _, v := range victims {
		if len(m) <= target {
			break
		}
		if len(m) <= limit && v.rank > lastRank && v.rank >= sprayRankVerdict {
			*floor = v.rank
			break
		}
		drop(v.key)
		lastRank = v.rank
	}
}
