package daemon

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// eximFrozenDedupTTL is how long an inactive queue ID remains tracked. Queue
// runs refresh the timestamp for messages that are still frozen, so one stuck
// message stays suppressed for its entire frozen lifetime. The expiry only
// bounds stale state when the daemon misses the corresponding unfreeze event.
const eximFrozenDedupTTL = 24 * time.Hour

// Sweep stale entries periodically instead of walking the entire map for every
// new frozen message. A burst of distinct frozen messages must remain O(n), not
// degrade to O(n^2) map scans.
const eximFrozenDedupPruneInterval = time.Hour

// Bound attacker-influenced queue state. Reaching the cap evicts an arbitrary
// older identity and therefore fails open to an occasional duplicate alert
// instead of allowing frozen-message churn to exhaust daemon memory.
const eximFrozenDedupMaxEntries = 10_000

// eximMessageIDPattern matches the exim queue ID as its own log field
// (e.g. "1wuZUi-0000000BrCR-0u0H"; older exims use shorter middle segments).
var eximMessageIDPattern = regexp.MustCompile(`^[0-9A-Za-z]{6}-[0-9A-Za-z]{6,11}-[0-9A-Za-z]{2,4}$`)

// eximFrozenDedup keeps the last-observed time per frozen message ID. Exim
// re-logs "Message is frozen" on every queue run for as long as the message
// stays queued, so without this one stuck bounce raises a finding every few
// minutes for days. In-memory on purpose: stale entries are bounded by the TTL,
// and losing the state on restart only costs one duplicate finding per
// still-frozen message.
var eximFrozenDedup = struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	nextPrune time.Time
}{seen: make(map[string]time.Time)}

func resetEximFrozenDedup() {
	eximFrozenDedup.mu.Lock()
	defer eximFrozenDedup.mu.Unlock()
	eximFrozenDedup.seen = make(map[string]time.Time)
	eximFrozenDedup.nextPrune = time.Time{}
}

type eximFrozenEvent uint8

const (
	eximFrozenEventNone eximFrozenEvent = iota
	eximFrozenEventFreeze
	eximFrozenEventUnfreeze
)

// eximFrozenShouldAlert reports whether a mainlog line is a freeze event that
// deserves a finding. Repeated queue-run notices for the same ID are
// suppressed, while an unfreeze event clears the ID so a later re-freeze is a
// new finding. Freeze-shaped lines with no parseable queue ID fail open.
func eximFrozenShouldAlert(line string, now time.Time) bool {
	id, event := parseEximFrozenEvent(line)
	if event == eximFrozenEventNone {
		return false
	}
	if event == eximFrozenEventUnfreeze {
		if id != "" {
			eximFrozenDedup.mu.Lock()
			delete(eximFrozenDedup.seen, id)
			eximFrozenDedup.mu.Unlock()
		}
		return false
	}
	if id == "" {
		return true
	}

	eximFrozenDedup.mu.Lock()
	defer eximFrozenDedup.mu.Unlock()
	if eximFrozenDedup.nextPrune.IsZero() || !now.Before(eximFrozenDedup.nextPrune) {
		cutoff := now.Add(-eximFrozenDedupTTL)
		for queuedID, lastSeen := range eximFrozenDedup.seen {
			if !lastSeen.After(cutoff) {
				delete(eximFrozenDedup.seen, queuedID)
			}
		}
		eximFrozenDedup.nextPrune = now.Add(eximFrozenDedupPruneInterval)
	}
	if lastSeen, ok := eximFrozenDedup.seen[id]; ok && now.Before(lastSeen.Add(eximFrozenDedupTTL)) {
		eximFrozenDedup.seen[id] = now
		return false
	}
	if _, tracked := eximFrozenDedup.seen[id]; !tracked && len(eximFrozenDedup.seen) >= eximFrozenDedupMaxEntries {
		for queuedID := range eximFrozenDedup.seen {
			delete(eximFrozenDedup.seen, queuedID)
			break
		}
	}
	eximFrozenDedup.seen[id] = now
	return true
}

// releaseEximFrozenDedup re-arms a freeze finding that the log watcher could
// not enqueue. Without this rollback, one full alert channel would discard the
// first finding and suppress every later queue-run reminder for that message.
func releaseEximFrozenDedup(line string) {
	id, event := parseEximFrozenEvent(line)
	if id == "" || event != eximFrozenEventFreeze {
		return
	}
	eximFrozenDedup.mu.Lock()
	delete(eximFrozenDedup.seen, id)
	eximFrozenDedup.mu.Unlock()
}

// parseEximFrozenEvent recognizes only Exim's action field, not arbitrary
// occurrences such as an attacker-controlled Subject containing "Frozen".
func parseEximFrozenEvent(line string) (string, eximFrozenEvent) {
	if !strings.Contains(line, "frozen") && !strings.Contains(line, "Frozen") {
		return "", eximFrozenEventNone
	}

	fields := strings.Fields(line)
	idIndex := eximMessageIDFieldIndex(fields)
	if idIndex >= 0 {
		return fields[idIndex], parseEximFrozenAction(fields[idIndex+1:])
	}

	// Preserve fail-open behavior for a future message-ID format, but only
	// when the field immediately after the candidate ID is an actual Exim
	// freeze action. Treating every ID-less occurrence of "frozen" as an event
	// lets subjects and router errors manufacture findings.
	payloadIndex := eximLogPayloadFieldIndex(fields)
	if payloadIndex < 0 {
		return "", eximFrozenEventNone
	}
	if event := parseEximFrozenAction(fields[payloadIndex:]); event != eximFrozenEventNone {
		return "", event
	}
	if event := parseEximFrozenAction(fields[payloadIndex+1:]); event != eximFrozenEventNone {
		return "", event
	}
	return "", eximFrozenEventNone
}

func parseEximFrozenAction(action []string) eximFrozenEvent {
	if len(action) == 0 {
		return eximFrozenEventNone
	}
	if strings.EqualFold(action[0], "unfrozen") {
		return eximFrozenEventUnfreeze
	}
	if strings.EqualFold(action[0], "frozen") {
		return eximFrozenEventFreeze
	}
	if len(action) >= 3 &&
		strings.EqualFold(action[0], "message") &&
		strings.EqualFold(action[1], "is") &&
		strings.EqualFold(action[2], "frozen") {
		return eximFrozenEventFreeze
	}
	return eximFrozenEventNone
}

// eximMessageIDFieldIndex locates the queue ID after the timestamp. Exim can
// insert a timezone and/or PID before it when log_timezone or the pid log
// selector is enabled.
func eximMessageIDFieldIndex(fields []string) int {
	index := eximLogPayloadFieldIndex(fields)
	if index < 0 || !eximMessageIDPattern.MatchString(fields[index]) {
		return -1
	}
	return index
}

func eximLogPayloadFieldIndex(fields []string) int {
	if len(fields) < 3 {
		return -1
	}
	index := 2
	for metadataFields := 0; metadataFields < 2 && index < len(fields); metadataFields++ {
		if !isEximLogTimezone(fields[index]) && !isEximLogPID(fields[index]) {
			break
		}
		index++
	}
	if index >= len(fields) {
		return -1
	}
	return index
}

func isEximLogTimezone(field string) bool {
	if len(field) != 5 || (field[0] != '+' && field[0] != '-') {
		return false
	}
	for _, c := range field[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isEximLogPID(field string) bool {
	if len(field) < 3 || field[0] != '[' || field[len(field)-1] != ']' {
		return false
	}
	for _, c := range field[1 : len(field)-1] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
