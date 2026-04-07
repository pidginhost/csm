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
		for ip, sr := range storeRecords {
			rec := &IPRecord{
				IP:           sr.IP,
				FirstSeen:    sr.FirstSeen,
				LastSeen:     sr.LastSeen,
				EventCount:   sr.EventCount,
				ThreatScore:  sr.ThreatScore,
				AutoBlocked:  sr.AutoBlocked,
				AttackCounts: make(map[AttackType]int),
				Accounts:     make(map[string]int),
			}
			for k, v := range sr.AttackCounts {
				rec.AttackCounts[AttackType(k)] = v
			}
			for k, v := range sr.Accounts {
				rec.Accounts[k] = v
			}
			db.records[ip] = rec
		}
		return
	}

	// Fallback: flat-file records.json.
	path := filepath.Join(db.dbPath, recordsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var records map[string]*IPRecord
	if err := json.Unmarshal(data, &records); err != nil {
		fmt.Fprintf(os.Stderr, "attackdb: error loading %s: %v\n", path, err)
		return
	}
	// Ensure maps are initialized
	for _, rec := range records {
		if rec.AttackCounts == nil {
			rec.AttackCounts = make(map[AttackType]int)
		}
		if rec.Accounts == nil {
			rec.Accounts = make(map[string]int)
		}
	}
	db.records = records
}

// saveRecords writes records to the bbolt store (if available) or to
// the flat-file records.json.
func (db *DB) saveRecords() {
	if sdb := store.Global(); sdb != nil {
		db.mu.RLock()
		for _, rec := range db.records {
			sr := store.IPRecord{
				IP:           rec.IP,
				FirstSeen:    rec.FirstSeen,
				LastSeen:     rec.LastSeen,
				EventCount:   rec.EventCount,
				ThreatScore:  rec.ThreatScore,
				AutoBlocked:  rec.AutoBlocked,
				AttackCounts: make(map[string]int),
				Accounts:     make(map[string]int),
			}
			for k, v := range rec.AttackCounts {
				sr.AttackCounts[string(k)] = v
			}
			for k, v := range rec.Accounts {
				sr.Accounts[k] = v
			}
			if err := sdb.SaveIPRecord(sr); err != nil {
				fmt.Fprintf(os.Stderr, "attackdb: store save %s: %v\n", rec.IP, err)
			}
		}
		db.mu.RUnlock()
		return
	}

	// Fallback: flat-file records.json.
	db.mu.RLock()
	data, err := json.Marshal(db.records)
	db.mu.RUnlock()

	if err != nil {
		fmt.Fprintf(os.Stderr, "attackdb: error marshaling records: %v\n", err)
		return
	}

	path := filepath.Join(db.dbPath, recordsFile)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "attackdb: error writing %s: %v\n", tmpPath, err)
		return
	}
	_ = os.Rename(tmpPath, path)
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
