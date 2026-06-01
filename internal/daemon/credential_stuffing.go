package daemon

import (
	"sort"
	"time"
)

// credentialStuffingDetector tracks, per source IP, the set of distinct
// accounts hit by auth failures inside a sliding window and flags an IP that
// targets many distinct accounts. This is the breadth signal of credential
// stuffing / password spraying -- one source trying many accounts, often with
// only one or two attempts each -- which the count-based pam_bruteforce
// detector (depth: many failures, any account) does not capture. CSM's auth
// sources never expose the attempted password, so the detector keys on the
// distinct-account behavioral signature rather than a password fingerprint.
//
// Concurrency: callers serialize access (the PAM listener holds its mutex
// across Record), so the detector takes no lock of its own.
type credentialStuffingDetector struct {
	distinctAccounts int
	window           time.Duration
	now              func() time.Time
	perIP            map[string]*credStuffState
	// maxTrackedIPs bounds the live map under sustained source-IP churn.
	// Once at the cap the oldest-by-lastSeen entry is evicted before insert.
	maxTrackedIPs int
}

type credStuffState struct {
	accounts  map[string]struct{}
	firstSeen time.Time
	lastSeen  time.Time
	// fired is set once the IP crosses the distinct-account threshold so a
	// single campaign yields one finding, not one per additional account.
	fired bool
}

// newCredentialStuffingDetector builds a detector. A distinctAccounts
// threshold below 2 has no breadth meaning and is clamped to 2.
func newCredentialStuffingDetector(distinctAccounts int, window time.Duration, now func() time.Time) *credentialStuffingDetector {
	if distinctAccounts < 2 {
		distinctAccounts = 2
	}
	if now == nil {
		now = time.Now
	}
	return &credentialStuffingDetector{
		distinctAccounts: distinctAccounts,
		window:           window,
		now:              now,
		perIP:            make(map[string]*credStuffState),
		maxTrackedIPs:    10000,
	}
}

// Record ingests one auth failure for (ip, account). It returns the sorted
// distinct-account list and true exactly once -- when the IP first crosses
// the distinct-account threshold inside the window. Empty ip or account is
// ignored. A failure whose IP has been silent longer than the window resets
// that IP's distinct set so a fresh campaign does not inherit cold counts.
func (d *credentialStuffingDetector) Record(ip, account string) ([]string, bool) {
	if d == nil || ip == "" || account == "" {
		return nil, false
	}
	now := d.now()
	state, ok := d.perIP[ip]
	if ok && now.Sub(state.lastSeen) > d.window {
		state = nil
		delete(d.perIP, ip)
	}
	if state == nil {
		if d.maxTrackedIPs > 0 && len(d.perIP) >= d.maxTrackedIPs {
			d.evictOldest()
		}
		state = &credStuffState{accounts: make(map[string]struct{}), firstSeen: now}
		d.perIP[ip] = state
	}
	state.accounts[account] = struct{}{}
	state.lastSeen = now

	if state.fired || len(state.accounts) < d.distinctAccounts {
		return nil, false
	}
	state.fired = true
	accounts := make([]string, 0, len(state.accounts))
	for a := range state.accounts {
		accounts = append(accounts, a)
	}
	sort.Strings(accounts)
	return accounts, true
}

// PruneStale drops per-IP entries whose lastSeen is older than the window.
// Called from the PAM listener cleanup loop so the detector does not grow
// without bound between window resets. Returns the number pruned.
func (d *credentialStuffingDetector) PruneStale(now time.Time) int {
	if d == nil {
		return 0
	}
	pruned := 0
	for ip, state := range d.perIP {
		if now.Sub(state.lastSeen) > d.window {
			delete(d.perIP, ip)
			pruned++
		}
	}
	return pruned
}

// evictOldest removes the entry with the smallest lastSeen so a fresh insert
// stays within maxTrackedIPs. Linear scan, bounded by the cap.
func (d *credentialStuffingDetector) evictOldest() {
	var oldestIP string
	var oldestAt time.Time
	first := true
	for ip, state := range d.perIP {
		if first || state.lastSeen.Before(oldestAt) {
			oldestIP, oldestAt, first = ip, state.lastSeen, false
		}
	}
	if oldestIP != "" {
		delete(d.perIP, oldestIP)
	}
}
