package daemon

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/emailspool"
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

// freezeErrIsAlreadyGone matches the Exim stderr fragments emitted when
// the message has already left the queue between snapshot and freeze.
// Those are not action failures -- they are normal queue churn.
func freezeErrIsAlreadyGone(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "message not found") ||
		strings.Contains(s, "spool file not found") ||
		strings.Contains(s, "no such message")
}

// spoolScanMatchingScript walks every -H file under spoolRoot, parses
// headers, and returns msgIDs whose X-PHP-Script host:path matches
// scriptKey. Used by AutoFreezePHPRelayQueue when activeMsgs was capped
// or when a late reputation finding has no in-memory activeMsgs left.
//
// Handles BOTH spool layouts:
//
//  1. Split (cPanel default + Exim's split_spool_directory=true): each
//     msgID-H lives under spoolRoot/<hash-char>/. We must descend one
//     level into each subdir.
//  2. Unsplit (some self-hosted Exim builds, smaller cPanel installs
//     where the operator has disabled split_spool_directory): -H files
//     live directly in spoolRoot.
//
// The spec section 5.8 explicitly requires both layouts. We probe each
// entry: if it's a regular -H file at the root, scan it; if it's a
// directory, descend. No probing of /etc/exim or spool config -- the
// filesystem layout is the source of truth.
//
//nolint:unused // wired in K5 by AutoFreezePHPRelayQueue
func spoolScanMatchingScript(spoolRoot string, k scriptKey) []string {
	var out []string
	// #nosec G304 -- spoolRoot is operator-configured / hardcoded to cPanel default.
	entries, err := os.ReadDir(spoolRoot)
	if err != nil {
		return nil
	}
	inspect := func(full string, name string) {
		if !strings.HasSuffix(name, "-H") {
			return
		}
		h, err := emailspool.ParseHeaders(full)
		if err != nil || h.XPHPScript == "" {
			return
		}
		sk, _ := parseXPHPScript(h.XPHPScript)
		if sk != k {
			return
		}
		id := strings.TrimSuffix(name, "-H")
		if msgIDPattern.MatchString(id) {
			out = append(out, id)
		}
	}
	for _, e := range entries {
		full := filepath.Join(spoolRoot, e.Name())
		if e.IsDir() {
			// Split layout: descend one level.
			// #nosec G304 -- spoolRoot is operator-configured / hardcoded to cPanel default.
			files, err := os.ReadDir(full)
			if err != nil {
				continue
			}
			for _, f := range files {
				inspect(filepath.Join(full, f.Name()), f.Name())
			}
			continue
		}
		// Unsplit layout: -H files at the root of spoolRoot.
		inspect(full, e.Name())
	}
	return out
}
