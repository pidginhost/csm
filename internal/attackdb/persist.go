package attackdb

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

const (
	recordsFile    = "records.json"
	eventsFile     = "events.jsonl"
	maxEventsBytes = 10 * 1024 * 1024 // 10 MB
)

// load reads IP records from the bbolt store (if available) or from
// the flat-file records.json.
func (db *DB) load() {
	if sdb := store.Global(); sdb != nil {
		storeRecords := sdb.LoadAllIPRecords()
		db.mu.Lock()
		defer db.mu.Unlock()
		if db.records == nil {
			db.records = make(map[string]*IPRecord, len(storeRecords))
		}
		for ip, sr := range storeRecords {
			rec := &IPRecord{
				IP:                    sr.IP,
				FirstSeen:             sr.FirstSeen,
				LastSeen:              sr.LastSeen,
				EventCount:            sr.EventCount,
				ThreatScore:           sr.ThreatScore,
				AutoBlocked:           sr.AutoBlocked,
				BruteForceWindowStart: sr.BruteForceWindowStart,
				BruteForceWindowCount: sr.BruteForceWindowCount,
				BruteForceSustainedAt: sr.BruteForceSustainedAt,
				AttackCounts:          make(map[AttackType]int),
				Accounts:              make(map[string]int),
			}
			for k, v := range sr.AttackCounts {
				rec.AttackCounts[AttackType(k)] = v
			}
			for k, v := range sr.Accounts {
				rec.Accounts[k] = v
			}
			if normalizeLoadedRecord(rec) {
				db.markDirtyLocked(ip)
			}
			db.records[ip] = rec
		}
		return
	}

	// Fallback: flat-file records.json.
	path := filepath.Join(db.dbPath, recordsFile)
	// #nosec G304 -- filepath.Join under operator-configured db.dbPath.
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var records map[string]*IPRecord
	if err := json.Unmarshal(data, &records); err != nil {
		fmt.Fprintf(os.Stderr, "attackdb: error loading %s: %v\n", path, err)
		return
	}
	db.mu.Lock()
	for ip, rec := range records {
		if normalizeLoadedRecord(rec) {
			db.markDirtyLocked(ip)
		}
	}
	db.records = records
	db.mu.Unlock()
}

func normalizeLoadedRecord(rec *IPRecord) bool {
	changed := false
	// Empty maps are an in-memory invariant; bbolt omits them, so nil-to-empty
	// alone should not dirty every account-free record on each startup.
	if rec.AttackCounts == nil {
		rec.AttackCounts = make(map[AttackType]int)
	}
	if rec.Accounts == nil {
		rec.Accounts = make(map[string]int)
	}
	bruteCount := rec.AttackCounts[AttackBruteForce]
	if rec.BruteForceWindowCount > bruteCount {
		rec.BruteForceWindowCount = bruteCount
		changed = true
	}
	if rec.BruteForceSustainedAt.IsZero() &&
		rec.BruteForceWindowCount >= sustainedBruteForceThreshold {
		rec.BruteForceSustainedAt = rec.LastSeen
		changed = true
	}
	score := ComputeScore(rec)
	if rec.ThreatScore != score {
		rec.ThreatScore = score
		changed = true
	}
	return changed
}

// saveRecords writes records to the bbolt store (if available) or to
// the flat-file records.json.
func (db *DB) saveRecords() {
	if sdb := store.Global(); sdb != nil {
		// Incremental: only records changed since the last flush are
		// re-serialized. On a host tracking tens of thousands of IPs the old
		// full rewrite cost seconds of CPU on every 30s flush and on shutdown.
		// Snapshot and clear the dirty set under the lock so concurrent
		// mutations land in the fresh set for the next flush; a write that
		// fails is re-marked dirty below so it retries.
		db.mu.Lock()
		dirty := db.dirtyIPs
		db.dirtyIPs = make(map[string]struct{})
		records := make([]store.IPRecord, 0, len(dirty))
		for ip := range dirty {
			rec, ok := db.records[ip]
			if !ok {
				continue // removed since marked; deletedIPs carries the removal
			}
			records = append(records, toStoreIPRecord(rec))
		}
		var deleted []string
		for ip := range db.deletedIPs {
			deleted = append(deleted, ip)
		}
		db.mu.Unlock()

		var failed []string
		for _, sr := range records {
			if err := sdb.SaveIPRecord(sr); err != nil {
				fmt.Fprintf(os.Stderr, "attackdb: store save %s: %v\n", sr.IP, err)
				failed = append(failed, sr.IP)
			}
		}
		if len(deleted) > 0 {
			var removed []string
			var failedDeletes []string
			for _, ip := range deleted {
				if err := sdb.DeleteIPRecord(ip); err != nil {
					fmt.Fprintf(os.Stderr, "attackdb: store delete %s: %v\n", ip, err)
					failedDeletes = append(failedDeletes, ip)
					continue
				}
				removed = append(removed, ip)
			}
			if len(removed) > 0 {
				db.mu.Lock()
				for _, ip := range removed {
					delete(db.deletedIPs, ip)
				}
				db.mu.Unlock()
			}
			if len(failedDeletes) > 0 {
				db.mu.Lock()
				db.dirty = true
				db.mu.Unlock()
			}
		}
		if len(failed) > 0 {
			db.mu.Lock()
			for _, ip := range failed {
				db.markDirtyLocked(ip)
			}
			db.mu.Unlock()
		}
		return
	}

	// Fallback: flat-file records.json. The whole records map is rewritten
	// each flush, so removals are reflected by absence and deletedIPs is
	// redundant here -- but it must still be drained or it grows for the
	// process lifetime on a host with no bbolt store. Snapshot under the same
	// lock as the marshal and swap dirtyIPs before disk I/O, so mutations
	// during the write land in a fresh set. Failed writes requeue the snapshot.
	db.mu.Lock()
	data, err := json.Marshal(db.records)
	var drained []string
	for ip := range db.deletedIPs {
		drained = append(drained, ip)
	}
	flushedDirty := db.dirtyIPs
	db.dirtyIPs = make(map[string]struct{})
	db.mu.Unlock()

	if err != nil {
		fmt.Fprintf(os.Stderr, "attackdb: error marshaling records: %v\n", err)
		db.requeueDirty(flushedDirty, len(drained) > 0)
		return
	}

	path := filepath.Join(db.dbPath, recordsFile)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "attackdb: error writing %s: %v\n", tmpPath, err)
		db.requeueDirty(flushedDirty, len(drained) > 0)
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		fmt.Fprintf(os.Stderr, "attackdb: error renaming %s: %v\n", path, err)
		db.requeueDirty(flushedDirty, len(drained) > 0)
		return
	}
	db.mu.Lock()
	for _, ip := range drained {
		delete(db.deletedIPs, ip)
	}
	db.mu.Unlock()
}

func (db *DB) requeueDirty(dirty map[string]struct{}, hasPendingDelete bool) {
	if len(dirty) == 0 && !hasPendingDelete {
		return
	}
	db.mu.Lock()
	if hasPendingDelete {
		db.dirty = true
	}
	for ip := range dirty {
		db.markDirtyLocked(ip)
	}
	db.mu.Unlock()
}

// toStoreIPRecord projects an in-memory record into the store's persistence
// shape, copying the count maps so the store never aliases live maps.
func toStoreIPRecord(rec *IPRecord) store.IPRecord {
	sr := store.IPRecord{
		IP:                    rec.IP,
		FirstSeen:             rec.FirstSeen,
		LastSeen:              rec.LastSeen,
		EventCount:            rec.EventCount,
		ThreatScore:           rec.ThreatScore,
		AutoBlocked:           rec.AutoBlocked,
		BruteForceWindowStart: rec.BruteForceWindowStart,
		BruteForceWindowCount: rec.BruteForceWindowCount,
		BruteForceSustainedAt: rec.BruteForceSustainedAt,
		AttackCounts:          make(map[string]int, len(rec.AttackCounts)),
		Accounts:              make(map[string]int, len(rec.Accounts)),
	}
	for k, v := range rec.AttackCounts {
		sr.AttackCounts[string(k)] = v
	}
	for k, v := range rec.Accounts {
		sr.Accounts[k] = v
	}
	return sr
}

// appendEvents writes events to the bbolt store (if available) or appends
// to the JSONL file, rotating if needed.
func (db *DB) appendEvents(events []Event) {
	if sdb := store.Global(); sdb != nil {
		for i, ev := range events {
			ts := ev.Timestamp
			if ts.IsZero() {
				ts = time.Now()
			}
			se := store.AttackEvent{
				Timestamp:  ts,
				IP:         ev.IP,
				AttackType: string(ev.AttackType),
				CheckName:  ev.CheckName,
				Severity:   ev.Severity,
				Account:    ev.Account,
				Message:    ev.Message,
			}
			if err := sdb.RecordAttackEvent(se, i); err != nil {
				fmt.Fprintf(os.Stderr, "attackdb: store event: %v\n", err)
			}
		}
		return
	}

	// Fallback: flat-file JSONL.
	path := filepath.Join(db.dbPath, eventsFile)

	// Check file size and rotate if needed
	if info, err := os.Stat(path); err == nil && info.Size() > maxEventsBytes {
		rotateEventsFile(path)
	}

	// #nosec G304 -- filepath.Join under operator-configured db.dbPath.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attackdb: error opening %s: %v\n", path, err)
		return
	}
	defer func() { _ = f.Close() }()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, ev := range events {
		_ = enc.Encode(ev)
	}
	_ = w.Flush()
}

// rotateEventsFile keeps the newest half of the file.
func rotateEventsFile(path string) {
	// #nosec G304 -- path is filepath.Join under operator-configured db.dbPath.
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// Find the midpoint newline
	mid := len(data) / 2
	for mid < len(data) {
		if data[mid] == '\n' {
			mid++
			break
		}
		mid++
	}
	if mid >= len(data) {
		return
	}

	tmpPath := path + ".tmp"
	// #nosec G703 -- path is db.path, derived from the operator-configured
	// statePath at DB open time (see Open / NewDB).
	if err := os.WriteFile(tmpPath, data[mid:], 0600); err != nil {
		return
	}
	_ = os.Rename(tmpPath, path)
}

// QueryEvents reads events for a specific IP from the bbolt store (if
// available) or from the JSONL file. Returns the most recent `limit`
// events in reverse chronological order.
func (db *DB) QueryEvents(ip string, limit int) []Event {
	if sdb := store.Global(); sdb != nil {
		storeEvents := sdb.QueryAttackEvents(ip, limit)
		result := make([]Event, len(storeEvents))
		for i, se := range storeEvents {
			result[i] = Event{
				Timestamp:  se.Timestamp,
				IP:         se.IP,
				AttackType: AttackType(se.AttackType),
				CheckName:  se.CheckName,
				Severity:   se.Severity,
				Account:    se.Account,
				Message:    se.Message,
			}
		}
		return result
	}

	// Fallback: flat-file JSONL.
	path := filepath.Join(db.dbPath, eventsFile)
	// #nosec G304 -- filepath.Join under operator-configured db.dbPath.
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var all []Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var ev Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if ev.IP == ip {
			all = append(all, ev)
		}
	}

	// Return most recent first
	if len(all) > limit && limit > 0 {
		all = all[len(all)-limit:]
	}
	// Reverse
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all
}
