package daemon

import (
	"regexp"
	"sync"
	"time"
)

// msgIDPattern guards exim -Mf invocations against header-injected garbage
// that slipped past parseHeaders. Exim msgIDs are <= 23 chars in practice
// but we accept up to 32 to allow for future format changes; the lower
// bound of 16 rules out any short string an attacker could try to slip in.
var msgIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{16,32}$`)

// eximBinary is resolved at module init via exec.LookPath. Empty means
// auto-action is permanently disabled (a Warning finding is emitted at
// startup -- see Phase O).
//
//nolint:unused // populated in K5 by AutoFreezePHPRelayQueue init via exec.LookPath
var eximBinary string

// actionRateLimiter is a sliding-window counter of exim -M* invocations.
// Per spec: at most maxPerMinute actions in any rolling 60s window.
type actionRateLimiter struct {
	mu         sync.Mutex
	maxPerMin  int
	bucket     int
	refilledAt time.Time
	now        func() time.Time
}

func newActionRateLimiter(maxPerMin int) *actionRateLimiter {
	return &actionRateLimiter{
		maxPerMin: maxPerMin,
		bucket:    maxPerMin,
		now:       time.Now,
	}
}

// consumeN returns true if n tokens were available and consumed.
//
//nolint:unused // wired in K5 by AutoFreezePHPRelayQueue
func (rl *actionRateLimiter) consumeN(n int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	if rl.refilledAt.IsZero() || now.Sub(rl.refilledAt) >= time.Minute {
		rl.bucket = rl.maxPerMin
		rl.refilledAt = now
	}
	if rl.bucket < n {
		return false
	}
	rl.bucket -= n
	return true
}
