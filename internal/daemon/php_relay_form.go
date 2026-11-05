package daemon

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/metrics"
)

const (
	formRelayMaxIPs          = 20000
	formRelayStaffTTL        = 7 * 24 * time.Hour
	formRelayStaffPerAccount = 64
)

// formRelayUnparsed prefixes the entry an unparsable message adds, keyed by
// its message ID. A parsed address never holds a NUL, so it cannot collide.
const formRelayUnparsed = "\x00"

// formRelayWindow is Path 6 state: the distinct outside recipients each
// client reached over the detection window, the clients seen on an
// authenticated admin page per account, and when each script was last
// reported. It is kept apart from perIPWindow, which Flow E sweeps after
// one idle hour, because bots post about hourly and the window is a day.
// All methods are safe for concurrent use.
type formRelayWindow struct {
	mu     sync.Mutex
	maxIPs int
	ips    map[string]*formRelayClient
	staff  map[string]map[string]time.Time // cpuser -> client key -> last admin mail
	// scriptFired is keyed by scriptID, which may name no script window.
	scriptFired map[scriptKey]time.Time
	hitCap      bool      // evicted a client since the last sweep
	now         time.Time // latest observation or sweep; replay cannot rewind expiry

	evictions *metrics.Counter // optional
}

type formRelayClient struct {
	exactIP  string
	lastSeen time.Time
	firedAt  time.Time
	rcpts    map[string]formRelayRcpt
}

type formRelayRcpt struct {
	at     time.Time
	script scriptKey
	cpuser string
	domain string // empty for an unparsed message
}

// formRelayShare is one script's part of a client's outside recipients.
// Raw is the newest recipient's script key, whose window holds its subjects.
type formRelayShare struct {
	Count  int
	CPUser string
	Raw    scriptKey
}

type formRelaySnapshot struct {
	Count      int
	Shares     map[scriptKey]formRelayShare
	Domains    []string
	FireClient bool
}

// evaluate captures one qualifying window and claims its client cooldown
// under the same lock. Expiry must not remove evidence between counting it
// and building the finding. Current exemptions also apply to older mail.
func (w *formRelayWindow) evaluate(key string, at time.Time, window time.Duration, spread int, ignored func(scriptKey) bool) formRelaySnapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := w.advanceLocked(at).Add(-window)
	c := w.ips[key]
	if c == nil || at.Before(cutoff) {
		return formRelaySnapshot{}
	}
	c.expire(cutoff)
	for r, v := range c.rcpts {
		if seenAtOrAfter(w.staff[v.cpuser][key], at.Add(-formRelayStaffTTL)) || ignored != nil && ignored(v.script) {
			delete(c.rcpts, r)
		}
	}
	if len(c.rcpts) < spread {
		return formRelaySnapshot{}
	}
	out := formRelaySnapshot{Count: len(c.rcpts), Shares: make(map[scriptKey]formRelayShare)}
	domains := make(map[string]struct{})
	newest := make(map[scriptKey]time.Time)
	for _, v := range c.rcpts {
		id := scriptID(v.script)
		share := out.Shares[id]
		share.Count++
		share.CPUser = v.cpuser
		if last := newest[id]; share.Raw == "" || v.at.After(last) || v.at.Equal(last) && v.script < share.Raw {
			newest[id], share.Raw = v.at, v.script
		}
		out.Shares[id] = share
		if v.domain != "" {
			domains[v.domain] = struct{}{}
		}
	}
	for domain := range domains {
		out.Domains = append(out.Domains, domain)
	}
	sort.Strings(out.Domains)
	if !seenAtOrAfter(c.firedAt, at.Add(-window)) {
		c.firedAt = at
		out.FireClient = true
	}
	return out
}

func newFormRelayWindow(maxIPs int) *formRelayWindow {
	return &formRelayWindow{
		maxIPs:      maxIPs,
		ips:         make(map[string]*formRelayClient),
		staff:       make(map[string]map[string]time.Time),
		scriptFired: make(map[scriptKey]time.Time),
	}
}

// formRelayKey is the client unit Path 6 counts: the IPv4 address, or the
// IPv6 /64, since one IPv6 customer gets a whole /64.
func formRelayKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	if a = a.Unmap(); a.Is4() {
		return a.String()
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}

// classifyFormRelayRecipients returns the lowercased recipients outside the
// account's listed domains (a subdomain needs its own entry, as in
// perIPWindow.appendMessage) and whether any recipient failed to parse. The
// attacker picks the address, so a parse failure, including a recipient
// block the spool parser could not validate (empty list), must still count.
func classifyFormRelayRecipients(rcpts []string, own map[string]struct{}) (outside []string, unparsed bool) {
	if len(rcpts) == 0 {
		return nil, true
	}
	for _, raw := range rcpts {
		r, domain := parseRelayRecipient(raw)
		if r == "" {
			unparsed = true
			continue
		}
		if _, ok := own[domain]; !ok {
			outside = append(outside, r)
		}
	}
	return outside, unparsed
}

// record adds one message's outside recipients for key and returns their
// distinct count, capped at limit, in the latest observed window. Delayed
// messages cannot rewind that window. An unparsed message adds one entry
// keyed by msgID. Retaining the newest recipients preserves later crossings
// when older evidence expires. An empty key is never stored.
func (w *formRelayWindow) record(key, exactIP, cpuser string, k scriptKey, msgID string, at time.Time, outside []string, unparsed bool, window time.Duration, limit int) int {
	if key == "" {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := w.advanceLocked(at).Add(-window)
	c := w.ips[key]
	if c == nil {
		if at.Before(cutoff) || len(outside) == 0 && !unparsed {
			return 0
		}
		c = w.addLocked(key, cutoff)
	}
	c.expire(cutoff)
	c.trim(limit)
	if at.Before(cutoff) {
		return len(c.rcpts)
	}
	if !at.Before(c.lastSeen) {
		c.lastSeen, c.exactIP = at, exactIP
	}
	for _, r := range outside {
		c.put(r, formRelayRcpt{at: at, script: k, cpuser: cpuser, domain: r[strings.LastIndexByte(r, '@')+1:]}, limit)
	}
	if unparsed {
		c.put(formRelayUnparsed+msgID, formRelayRcpt{at: at, script: k, cpuser: cpuser}, limit)
	}
	return len(c.rcpts)
}

// put stores r, or refreshes it so the latest message's script owns it.
func (c *formRelayClient) put(r string, v formRelayRcpt, limit int) {
	if old, ok := c.rcpts[r]; ok {
		if !v.at.Before(old.at) {
			c.rcpts[r] = v
		}
		return
	}
	c.rcpts[r] = v
	c.trim(limit)
}

func (c *formRelayClient) trim(limit int) {
	for len(c.rcpts) > limit {
		var oldest string
		var at time.Time
		for r, v := range c.rcpts {
			if oldest == "" || v.at.Before(at) {
				oldest, at = r, v.at
			}
		}
		delete(c.rcpts, oldest)
	}
}

func (c *formRelayClient) expire(cutoff time.Time) {
	for r, v := range c.rcpts {
		if v.at.Before(cutoff) {
			delete(c.rcpts, r)
		}
	}
}

func (w *formRelayWindow) advanceLocked(at time.Time) time.Time {
	if at.After(w.now) {
		w.now = at
	}
	return w.now
}

func (w *formRelayWindow) expireClientsLocked(cutoff time.Time) {
	for key, c := range w.ips {
		c.expire(cutoff)
		if len(c.rcpts) == 0 && !seenAtOrAfter(c.firedAt, cutoff) {
			delete(w.ips, key)
		}
	}
}

func (w *formRelayWindow) addLocked(key string, cutoff time.Time) *formRelayClient {
	if len(w.ips) >= w.maxIPs {
		w.expireClientsLocked(cutoff)
	}
	if len(w.ips) >= w.maxIPs {
		w.evictLocked()
	}
	c := &formRelayClient{rcpts: make(map[string]formRelayRcpt, 4)}
	w.ips[key] = c
	return c
}

// evictLocked drops the client with the fewest recipients, the oldest among
// equals. That minimum is never a client at or above half the threshold
// while a lower one exists, so flooding the table with one-recipient
// clients cannot push out one close to crossing; when every client is at or
// above half, the lowest and oldest still goes.
func (w *formRelayWindow) evictLocked() {
	// ponytail: O(n) scan only at the cap; bucket by count if floods make it hot.
	var victim string
	var low *formRelayClient
	for key, c := range w.ips {
		if low == nil || len(c.rcpts) < len(low.rcpts) ||
			len(c.rcpts) == len(low.rcpts) && c.lastSeen.Before(low.lastSeen) {
			victim, low = key, c
		}
	}
	if low != nil {
		delete(w.ips, victim)
		w.hitCap = true
		if w.evictions != nil {
			w.evictions.Inc()
		}
	}
}

// count returns the distinct outside recipients key reached since since.
// It only reads: no expiry, no clock advance.
func (w *formRelayWindow) count(key string, since time.Time) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	if c := w.ips[key]; c != nil {
		for _, v := range c.rcpts {
			if !v.at.Before(since) {
				n++
			}
		}
	}
	return n
}

// exactIP returns the last exact address seen for key.
func (w *formRelayWindow) exactIP(key string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if c := w.ips[key]; c != nil {
		return c.exactIP
	}
	return ""
}

// scriptShares returns the distinct outside recipients each script reached
// for key since since, with that script's account.
func (w *formRelayWindow) scriptShares(key string, since time.Time) map[scriptKey]formRelayShare {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[scriptKey]formRelayShare)
	if c := w.ips[key]; c != nil {
		for _, v := range c.rcpts {
			if v.at.Before(since) {
				continue
			}
			s := out[v.script]
			s.Count++
			s.CPUser = v.cpuser
			out[v.script] = s
		}
	}
	return out
}

// recipientDomains returns the sorted outside domains key reached since
// since. Full addresses stay out of findings: they belong to third parties.
func (w *formRelayWindow) recipientDomains(key string, since time.Time) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	c := w.ips[key]
	if c == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(c.rcpts))
	out := make([]string, 0, len(c.rcpts))
	for _, v := range c.rcpts {
		if v.domain == "" || v.at.Before(since) {
			continue
		}
		if _, dup := seen[v.domain]; !dup {
			seen[v.domain] = struct{}{}
			out = append(out, v.domain)
		}
	}
	sort.Strings(out)
	return out
}

// markFired reports true once per key per window, never for an empty key.
func (w *formRelayWindow) markFired(key string, at time.Time, window time.Duration) bool {
	if key == "" {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := w.advanceLocked(at).Add(-window)
	if at.Before(cutoff) {
		return false
	}
	c := w.ips[key]
	if c == nil {
		c = w.addLocked(key, cutoff)
	}
	if seenAtOrAfter(c.firedAt, at.Add(-window)) {
		return false
	}
	c.firedAt = at
	return true
}

// claimScript reports true once per script id per window.
func (w *formRelayWindow) claimScript(id scriptKey, at time.Time, window time.Duration) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if seenAtOrAfter(w.scriptFired[id], at.Add(-window)) {
		return false
	}
	w.scriptFired[id] = at
	return true
}

// markStaff records that key sent mail through an authenticated admin page
// of cpuser. Each account keeps its newest formRelayStaffPerAccount keys.
func (w *formRelayWindow) markStaff(cpuser, key string, at time.Time) {
	if key == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	keys := w.staff[cpuser]
	if keys == nil {
		keys = make(map[string]time.Time, 1)
		w.staff[cpuser] = keys
	}
	if at.After(keys[key]) {
		keys[key] = at
	}
	if len(keys) > formRelayStaffPerAccount {
		evictOldestRecipient(keys)
	}
}

func (w *formRelayWindow) isStaff(cpuser, key string, at time.Time) bool {
	if key == "" {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return seenAtOrAfter(w.staff[cpuser][key], at.Add(-formRelayStaffTTL))
}

// sweep drops expired recipients, clients with nothing left in the window,
// script reports older than the window and expired staff, and reports
// whether the table hit its cap since the last sweep.
func (w *formRelayWindow) sweep(now time.Time, window time.Duration) (evictedFull bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now = w.advanceLocked(now)
	w.expireClientsLocked(now.Add(-window))
	for id, at := range w.scriptFired {
		if !seenAtOrAfter(at, now.Add(-window)) {
			delete(w.scriptFired, id)
		}
	}
	staffCutoff := now.Add(-formRelayStaffTTL)
	for user, keys := range w.staff {
		for key, at := range keys {
			if at.Before(staffCutoff) {
				delete(keys, key)
			}
		}
		if len(keys) == 0 {
			delete(w.staff, user)
		}
	}
	evictedFull, w.hitCap = w.hitCap, false
	return evictedFull
}

// full reports whether the table hit its cap since the last sweep.
func (w *formRelayWindow) full() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hitCap
}
