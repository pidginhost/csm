package daemon

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
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
// client reached over the detection window, and the clients seen on an
// authenticated admin page per account. It is kept apart from perIPWindow,
// which Flow E sweeps after one idle hour, because bots post about hourly
// and the window is a day. All methods are safe for concurrent use.
type formRelayWindow struct {
	mu     sync.Mutex
	maxIPs int
	ips    map[string]*formRelayClient
	staff  map[string]map[string]time.Time // cpuser -> client key -> last admin mail
	hitCap bool                            // evicted a client since the last sweep
	now    time.Time                       // latest observation or sweep; replay cannot rewind expiry
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
type formRelayShare struct {
	Count  int
	CPUser string
}

func newFormRelayWindow(maxIPs int) *formRelayWindow {
	return &formRelayWindow{
		maxIPs: maxIPs,
		ips:    make(map[string]*formRelayClient),
		staff:  make(map[string]map[string]time.Time),
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
// when older evidence expires.
func (w *formRelayWindow) record(key, exactIP, cpuser string, k scriptKey, msgID string, at time.Time, outside []string, unparsed bool, window time.Duration, limit int) int {
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
	}
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

// markFired reports true once per key per window.
func (w *formRelayWindow) markFired(key string, at time.Time, window time.Duration) bool {
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

// markStaff records that key sent mail through an authenticated admin page
// of cpuser. Each account keeps its newest formRelayStaffPerAccount keys.
func (w *formRelayWindow) markStaff(cpuser, key string, at time.Time) {
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
	w.mu.Lock()
	defer w.mu.Unlock()
	return seenAtOrAfter(w.staff[cpuser][key], at.Add(-formRelayStaffTTL))
}

// sweep drops expired recipients, clients with nothing left in the window
// and expired staff, and reports whether the table hit its cap since the
// last sweep.
func (w *formRelayWindow) sweep(now time.Time, window time.Duration) (evictedFull bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now = w.advanceLocked(now)
	w.expireClientsLocked(now.Add(-window))
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
