package attackdb

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	recordsFile    = "records.json"
	eventsFile     = "events.jsonl"
	maxEventsBytes = 10 * 1024 * 1024 // 10 MB
)

// load reads the records file from disk into memory.
func (db *DB) load() {
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

// saveRecords writes the records map to disk atomically.
func (db *DB) saveRecords() {
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

// appendEvents appends events to the JSONL file, rotating if needed.
func (db *DB) appendEvents(events []Event) {
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

// QueryEvents reads events for a specific IP from the JSONL file.
// Returns the most recent `limit` events in reverse chronological order.
func (db *DB) QueryEvents(ip string, limit int) []Event {
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
