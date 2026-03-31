package daemon

import (
	"sync"
	"time"
)

const purgeSuppressionWindow = 60 * time.Second

// purgeTracker correlates password purge events with subsequent
// stale-session 401 errors to suppress false-positive alerts.
//
// When a cPanel user changes their password, all existing sessions are
// invalidated. Any in-flight browser requests (AJAX polls, notifications,
// etc.) will return 401 — these are expected side effects, not attacks.
//
// Flow: login (NEW) records IP→account, PURGE records account→time,
// 401 handler checks IP→account→purgeTime to decide suppression.
var purgeTracker = &purgeState{
	purges:   make(map[string]time.Time),
	sessions: make(map[string]string),
}

type purgeState struct {
	mu       sync.Mutex
	purges   map[string]time.Time // account → last purge time
	sessions map[string]string    // IP → last known account
}

// recordLogin tracks which account an IP most recently logged into.
func (ps *purgeState) recordLogin(ip, account string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.sessions[ip] = account
	ps.cleanupLocked()
}

// recordPurge records a password purge event for an account.
func (ps *purgeState) recordPurge(account string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.purges[account] = time.Now()
}

// isPostPurge401 returns true if the IP's 401 is likely a stale session
// artifact from a recent password change (within the suppression window).
func (ps *purgeState) isPostPurge401(ip string) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	account, ok := ps.sessions[ip]
	if !ok {
		return false
	}
	purgeTime, ok := ps.purges[account]
	if !ok {
		return false
	}
	return time.Since(purgeTime) < purgeSuppressionWindow
}

// cleanupLocked removes stale entries. Caller must hold ps.mu.
func (ps *purgeState) cleanupLocked() {
	cutoff := time.Now().Add(-2 * purgeSuppressionWindow)
	for k, t := range ps.purges {
		if t.Before(cutoff) {
			delete(ps.purges, k)
		}
	}
	// Cap sessions map to prevent unbounded growth (keep most recent 500)
	if len(ps.sessions) > 500 {
		ps.sessions = make(map[string]string)
	}
}
