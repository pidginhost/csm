package daemon

import (
	"container/list"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/store"
)

// eximFrozenDedupTTL is how long an inactive queue ID remains tracked. Queue
// runs refresh the timestamp for messages that are still frozen, so one stuck
// message stays suppressed for its entire frozen lifetime. The expiry only
// bounds stale state when the daemon misses the corresponding unfreeze event,
// for example when a frozen message is removed from the queue, which exim logs
// without an unfreeze line.
const eximFrozenDedupTTL = 24 * time.Hour

// Sweep stale entries periodically instead of walking the entire table for
// every new frozen message. A burst of distinct frozen messages must remain
// O(n), not degrade to O(n^2) scans; eviction at capacity is constant time for
// the same reason.
const eximFrozenDedupPruneInterval = time.Hour

// Bound attacker-influenced queue state. Every tracked ID is a real message
// exim froze (the parser reads only exim's own queue-ID field), so filling
// the table takes that many frozen messages inside one TTL, each of which
// raised its own finding. Reaching the cap evicts the ID no queue run has
// refreshed for the longest, so the cost of overflow is a duplicate finding
// for an old message, never a missed report for a new one.
const eximFrozenDedupMaxEntries = 10_000

// eximFrozenDedupPersistInterval is how often changed dedup state is written
// to the state store. A clean shutdown writes it once more after the log
// watchers stop, so only a crash can lose the IDs first seen inside the last
// interval, and each of those is reported once more after the restart. A var
// so tests can drive the periodic writer without waiting a minute.
var eximFrozenDedupPersistInterval = time.Minute

// eximMessageIDPattern matches the exim queue ID as its own log field
// (e.g. "1wuZUi-0000000BrCR-0u0H"; older exims use shorter middle segments).
var eximMessageIDPattern = regexp.MustCompile(`^[0-9A-Za-z]{6}-[0-9A-Za-z]{6,11}-[0-9A-Za-z]{2,4}$`)

// eximFrozenDedup keeps the last-observed time per frozen message ID. Exim
// re-logs "Message is frozen" on every queue run for as long as the message
// stays queued, so without this one stuck bounce raises a finding every few
// minutes for days. The table is persisted to the state store: the first
// queue run after a restart re-logs every still-frozen message, and only a
// message the daemon never saw frozen may alert then. Seeding the table from
// the queue at startup instead would hide a message that froze while the
// daemon was down.
var eximFrozenDedup = struct {
	mu   sync.Mutex
	seen map[string]*list.Element
	// order holds one *eximFrozenSighting per tracked ID, least recently
	// seen first, so eviction at capacity drops the stalest ID without a scan.
	order     *list.List
	nextPrune time.Time
	// version counts changes to the table; persisted is the version the state
	// store last accepted. They differ while there is something to save.
	version   uint64
	persisted uint64
}{seen: make(map[string]*list.Element), order: list.New()}

type eximFrozenSighting struct {
	id       string
	lastSeen time.Time
}

func resetEximFrozenDedup() {
	eximFrozenDedup.mu.Lock()
	defer eximFrozenDedup.mu.Unlock()
	eximFrozenDedup.seen = make(map[string]*list.Element)
	eximFrozenDedup.order = list.New()
	eximFrozenDedup.nextPrune = time.Time{}
	eximFrozenDedup.version = 0
	eximFrozenDedup.persisted = 0
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
			forgetEximFrozenID(id)
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
		for el := eximFrozenDedup.order.Front(); el != nil; {
			next := el.Next()
			if sighting := el.Value.(*eximFrozenSighting); !sighting.lastSeen.After(cutoff) {
				removeEximFrozenSightingLocked(el)
			}
			el = next
		}
		eximFrozenDedup.nextPrune = now.Add(eximFrozenDedupPruneInterval)
	}
	eximFrozenDedup.version++
	if el, ok := eximFrozenDedup.seen[id]; ok {
		sighting := el.Value.(*eximFrozenSighting)
		suppressed := now.Before(sighting.lastSeen.Add(eximFrozenDedupTTL))
		sighting.lastSeen = now
		eximFrozenDedup.order.MoveToBack(el)
		return !suppressed
	}
	if eximFrozenDedup.order.Len() >= eximFrozenDedupMaxEntries {
		removeEximFrozenSightingLocked(eximFrozenDedup.order.Front())
	}
	eximFrozenDedup.seen[id] = eximFrozenDedup.order.PushBack(&eximFrozenSighting{id: id, lastSeen: now})
	return true
}

func removeEximFrozenSightingLocked(el *list.Element) {
	delete(eximFrozenDedup.seen, el.Value.(*eximFrozenSighting).id)
	eximFrozenDedup.order.Remove(el)
}

func forgetEximFrozenID(id string) {
	eximFrozenDedup.mu.Lock()
	defer eximFrozenDedup.mu.Unlock()
	if el, ok := eximFrozenDedup.seen[id]; ok {
		removeEximFrozenSightingLocked(el)
		eximFrozenDedup.version++
	}
}

// loadEximFrozenDedup replaces the table with the persisted one. It runs
// before the log watchers start, so the replacement discards nothing they
// recorded. Entries past the TTL, entries that are not exim queue IDs, and
// any excess over the cap (oldest first) are dropped, so the restored table
// obeys the same bounds as one built from the log. A last-seen time ahead of
// now counts as now, so a clock step back cannot stretch suppression past the
// TTL.
func loadEximFrozenDedup(db *store.DB, now time.Time) error {
	persisted, err := db.LoadEximFrozenSeen()
	if err != nil {
		return err
	}
	cutoff := now.Add(-eximFrozenDedupTTL)
	restored := make([]*eximFrozenSighting, 0, len(persisted))
	corrected := false
	for id, lastSeen := range persisted {
		if !eximMessageIDPattern.MatchString(id) || !lastSeen.After(cutoff) {
			corrected = true
			continue
		}
		if lastSeen.After(now) {
			lastSeen = now
			corrected = true
		}
		restored = append(restored, &eximFrozenSighting{id: id, lastSeen: lastSeen})
	}
	sort.Slice(restored, func(i, j int) bool {
		return restored[i].lastSeen.Before(restored[j].lastSeen)
	})
	if excess := len(restored) - eximFrozenDedupMaxEntries; excess > 0 {
		restored = restored[excess:]
		corrected = true
	}

	seen := make(map[string]*list.Element, len(restored))
	order := list.New()
	for _, sighting := range restored {
		seen[sighting.id] = order.PushBack(sighting)
	}
	eximFrozenDedup.mu.Lock()
	eximFrozenDedup.seen = seen
	eximFrozenDedup.order = order
	if corrected {
		// Save cleanup even if no queue run follows. Otherwise each restart
		// clamps the same future timestamp again and extends suppression.
		eximFrozenDedup.version++
	}
	eximFrozenDedup.mu.Unlock()
	return nil
}

// saveEximFrozenDedup writes the table to the state store when it changed
// since the last successful save. Callers serialize saves: the periodic
// writer exits before the final shutdown save runs.
func saveEximFrozenDedup(db *store.DB) error {
	eximFrozenDedup.mu.Lock()
	if eximFrozenDedup.version == eximFrozenDedup.persisted {
		eximFrozenDedup.mu.Unlock()
		return nil
	}
	version := eximFrozenDedup.version
	snapshot := make(map[string]time.Time, eximFrozenDedup.order.Len())
	for el := eximFrozenDedup.order.Front(); el != nil; el = el.Next() {
		sighting := el.Value.(*eximFrozenSighting)
		snapshot[sighting.id] = sighting.lastSeen
	}
	eximFrozenDedup.mu.Unlock()

	if err := db.SaveEximFrozenSeen(snapshot); err != nil {
		return err
	}
	eximFrozenDedup.mu.Lock()
	eximFrozenDedup.persisted = version
	eximFrozenDedup.mu.Unlock()
	return nil
}

// restoreEximFrozenDedup loads the persisted frozen-message table. Without a
// state store the daemon keeps the table in memory only.
func (d *Daemon) restoreEximFrozenDedup() {
	if sdb := store.Global(); sdb != nil {
		if err := loadEximFrozenDedup(sdb, time.Now()); err != nil {
			csmlog.Warn("exim frozen-message dedup load failed", "err", err)
		}
	}
}

// persistEximFrozenDedup saves the frozen-message table if it changed.
func (d *Daemon) persistEximFrozenDedup() {
	if sdb := store.Global(); sdb != nil {
		if err := saveEximFrozenDedup(sdb); err != nil {
			csmlog.Warn("exim frozen-message dedup persistence failed", "err", err)
		}
	}
}

// startEximFrozenDedupPersistence saves changed dedup state periodically while
// the exim mainlog is watched. It stops on d.stopCh without a final save; the
// shutdown path saves once more after every log watcher has exited.
func (d *Daemon) startEximFrozenDedupPersistence() {
	d.wg.Add(1)
	obs.Go("exim-frozen-dedup-persist", func() {
		defer d.wg.Done()
		ticker := time.NewTicker(eximFrozenDedupPersistInterval)
		defer ticker.Stop()
		for {
			select {
			case <-d.stopCh:
				return
			case <-ticker.C:
				d.persistEximFrozenDedup()
			}
		}
	})
}

// releaseEximFrozenDedup re-arms a freeze finding that the log watcher could
// not enqueue. Without this rollback, one full alert channel would discard the
// first finding and suppress every later queue-run reminder for that message.
func releaseEximFrozenDedup(line string) {
	id, event := parseEximFrozenEvent(line)
	if id == "" || event != eximFrozenEventFreeze {
		return
	}
	forgetEximFrozenID(id)
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
