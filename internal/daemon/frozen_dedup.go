package daemon

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// eximFrozenDedupTTL is how long one queued message's frozen state stays
// suppressed after its first finding. A message still frozen a day later is
// worth a fresh alert.
const eximFrozenDedupTTL = 24 * time.Hour

// eximMessageIDPattern matches the exim queue ID as its own log field
// (e.g. "1wuZUi-0000000BrCR-0u0H"; older exims use shorter middle segments).
var eximMessageIDPattern = regexp.MustCompile(`^[0-9A-Za-z]{6}-[0-9A-Za-z]{6,11}-[0-9A-Za-z]{2,4}$`)

// eximFrozenDedup keeps the first-alert time per frozen message ID. Exim
// re-logs "Message is frozen" on every queue run for as long as the message
// stays queued, so without this one stuck bounce raises a finding every few
// minutes for days. In-memory on purpose: cardinality is unbounded, so the
// state must not accrete in the bbolt meta bucket, and losing it on restart
// only costs one duplicate finding per still-frozen message.
var eximFrozenDedup = struct {
	mu   sync.Mutex
	seen map[string]time.Time
}{seen: make(map[string]time.Time)}

func resetEximFrozenDedup() {
	eximFrozenDedup.mu.Lock()
	defer eximFrozenDedup.mu.Unlock()
	eximFrozenDedup.seen = make(map[string]time.Time)
}

// eximFrozenShouldAlert reports whether a mainlog line containing "frozen"
// deserves a finding: unfreeze events never do, and freeze events for a
// message already alerted on within the TTL are suppressed. Lines with no
// parseable queue ID fail open.
func eximFrozenShouldAlert(line string, now time.Time) bool {
	if strings.Contains(line, "Unfrozen") {
		return false
	}
	id := extractEximMessageID(line)
	if id == "" {
		return true
	}

	eximFrozenDedup.mu.Lock()
	defer eximFrozenDedup.mu.Unlock()
	if ts, ok := eximFrozenDedup.seen[id]; ok && now.Sub(ts) < eximFrozenDedupTTL {
		return false
	}
	for k, ts := range eximFrozenDedup.seen {
		if now.Sub(ts) >= eximFrozenDedupTTL {
			delete(eximFrozenDedup.seen, k)
		}
	}
	eximFrozenDedup.seen[id] = now
	return true
}

// extractEximMessageID returns the queue ID from a mainlog line, where it is
// the third whitespace-separated field ("<date> <time> <id> ..."), or "" when
// the field is absent or not ID-shaped.
func extractEximMessageID(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return ""
	}
	if eximMessageIDPattern.MatchString(fields[2]) {
		return fields[2]
	}
	return ""
}
