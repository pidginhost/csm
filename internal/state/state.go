package state

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
)

type Store struct {
	mu        sync.RWMutex
	path      string
	entries   map[string]*Entry
	dirty     bool   // true if state changed since last save
	savedHash string // hash of last saved state

	// LatestFindings holds the full output of the most recent scan cycle.
	// This is what the Findings page shows — "what's wrong right now" —
	// separate from the alert dedup state above which controls "what to email."
	latestMu       sync.RWMutex
	latestFindings []alert.Finding
	latestScanTime time.Time
}

type Entry struct {
	Hash       string    `json:"hash"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	AlertSent  time.Time `json:"alert_sent"`
	IsBaseline bool      `json:"is_baseline"`
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, fmt.Errorf("creating state dir: %w", err)
	}

	s := &Store{
		path:    path,
		entries: make(map[string]*Entry),
	}

	stateFile := filepath.Join(path, "state.json")
	data, err := os.ReadFile(stateFile)
	if err == nil {
		_ = json.Unmarshal(data, &s.entries)
	}

	return s, nil
}

func (s *Store) Close() error {
	if !s.dirty {
		return nil
	}
	return s.save()
}

func (s *Store) save() error {
	data, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return err
	}

	// Skip write if content hasn't changed
	newHash := fmt.Sprintf("%x", sha256.Sum256(data))
	if newHash == s.savedHash {
		s.dirty = false
		return nil
	}

	// Atomic write: write to temp file, then rename
	stateFile := filepath.Join(s.path, "state.json")
	tmpFile := stateFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpFile, stateFile); err != nil {
		os.Remove(tmpFile)
		return err
	}

	s.savedHash = newHash
	s.dirty = false
	return nil
}

func findingKey(f alert.Finding) string {
	return fmt.Sprintf("%s:%s", f.Check, f.Message)
}

func findingHash(f alert.Finding) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", f.Check, f.Message, f.Details)))
	return fmt.Sprintf("%x", h[:8])
}

func (s *Store) FilterNew(findings []alert.Finding) []alert.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var newFindings []alert.Finding

	for _, f := range findings {
		key := findingKey(f)
		hash := findingHash(f)

		entry, exists := s.entries[key]
		if !exists {
			newFindings = append(newFindings, f)
			continue
		}

		if entry.IsBaseline && entry.Hash == hash {
			continue
		}

		if entry.Hash != hash {
			newFindings = append(newFindings, f)
			continue
		}

		// Same finding, check if we should re-alert (state expiry)
		if !entry.AlertSent.IsZero() && time.Since(entry.AlertSent) > 24*time.Hour {
			newFindings = append(newFindings, f)
		}
	}

	return newFindings
}

func (s *Store) Update(findings []alert.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = true
	now := time.Now()

	seen := make(map[string]bool)
	for _, f := range findings {
		key := findingKey(f)
		hash := findingHash(f)
		seen[key] = true

		entry, exists := s.entries[key]
		if !exists {
			s.entries[key] = &Entry{
				Hash:      hash,
				FirstSeen: now,
				LastSeen:  now,
				AlertSent: now,
			}
		} else {
			entry.Hash = hash
			entry.LastSeen = now
			if entry.AlertSent.IsZero() {
				entry.AlertSent = now
			}
		}
	}

	// Clean up entries that are no longer found
	for key, entry := range s.entries {
		if !seen[key] && !entry.IsBaseline {
			if time.Since(entry.LastSeen) > 24*time.Hour {
				delete(s.entries, key)
			}
		}
	}

	_ = s.save()
}

func (s *Store) SetBaseline(findings []alert.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = true
	s.entries = make(map[string]*Entry)
	now := time.Now()

	for _, f := range findings {
		key := findingKey(f)
		hash := findingHash(f)
		s.entries[key] = &Entry{
			Hash:       hash,
			FirstSeen:  now,
			LastSeen:   now,
			IsBaseline: true,
		}
	}

	_ = s.save()
}

func (s *Store) ShouldRunThrottled(checkName string, intervalMin int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("_throttle:%s", checkName)
	entry, exists := s.entries[key]
	if !exists {
		s.entries[key] = &Entry{LastSeen: time.Now()}
		return true
	}
	if time.Since(entry.LastSeen) >= time.Duration(intervalMin)*time.Minute {
		entry.LastSeen = time.Now()
		return true
	}
	return false
}

func (s *Store) GetRaw(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[key]
	if !ok {
		return "", false
	}
	return entry.Hash, true
}

func (s *Store) SetRaw(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.entries[key]
	if !exists {
		s.entries[key] = &Entry{
			Hash:      value,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		s.dirty = true
	} else if entry.Hash != value {
		entry.Hash = value
		entry.LastSeen = time.Now()
		s.dirty = true
	}
}

// AppendHistory writes findings to an append-only JSONL history file.
// Caps file at 10MB by truncating the oldest half.
func (s *Store) AppendHistory(findings []alert.Finding) {
	if len(findings) == 0 {
		return
	}

	histPath := filepath.Join(s.path, "history.jsonl")

	// Check size, truncate if over 10MB
	if info, err := os.Stat(histPath); err == nil && info.Size() > 10*1024*1024 {
		data, err := os.ReadFile(histPath)
		if err == nil {
			// Keep the second half
			half := len(data) / 2
			for half < len(data) && data[half] != '\n' {
				half++
			}
			if half < len(data) {
				_ = os.WriteFile(histPath, data[half+1:], 0600)
			}
		}
	}

	f, err := os.OpenFile(histPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	for _, finding := range findings {
		line, err := json.Marshal(finding)
		if err != nil {
			continue
		}
		_, _ = f.Write(line)
		_, _ = f.Write([]byte("\n"))
	}
}

func (s *Store) PrintStatus() {
	if len(s.entries) == 0 {
		fmt.Println("No state entries. Run 'csm baseline' first.")
		return
	}

	baselineCount := 0
	activeCount := 0
	for key, entry := range s.entries {
		if entry.IsBaseline {
			baselineCount++
			continue
		}
		if key[0] == '_' {
			continue
		}
		activeCount++
		fmt.Printf("  [ACTIVE] %s (first: %s, last: %s)\n",
			key,
			entry.FirstSeen.Format("2006-01-02 15:04"),
			entry.LastSeen.Format("2006-01-02 15:04"),
		)
	}
	fmt.Printf("\nBaseline entries: %d, Active findings: %d\n", baselineCount, activeCount)
}

// Entries returns a snapshot copy of current state entries (thread-safe).
func (s *Store) Entries() map[string]*Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	copy := make(map[string]*Entry, len(s.entries))
	for k, v := range s.entries {
		if k[0] == '_' {
			continue // skip internal keys
		}
		entryCopy := *v
		copy[k] = &entryCopy
	}
	return copy
}

// ReadHistory reads the last limit entries from history.jsonl, starting at offset.
// Returns the findings (newest first) and total count.
func (s *Store) ReadHistory(limit, offset int) ([]alert.Finding, int) {
	historyPath := filepath.Join(s.path, "history.jsonl")
	data, err := os.ReadFile(historyPath)
	if err != nil {
		return nil, 0
	}

	var all []alert.Finding
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var f alert.Finding
		if err := json.Unmarshal(line, &f); err != nil {
			continue
		}
		all = append(all, f)
	}

	// Reverse (newest first)
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}

	total := len(all)
	if offset >= total {
		return nil, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// SetLatestFindings stores the full results of the most recent scan cycle.
// Called by the daemon after each periodic scan completes.
func (s *Store) SetLatestFindings(findings []alert.Finding) {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()

	// Deduplicate by check:message (keep the most recent per key)
	seen := make(map[string]bool)
	var deduped []alert.Finding
	for _, f := range findings {
		key := f.Check + ":" + f.Message
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, f)
		}
	}
	s.latestFindings = deduped
	s.latestScanTime = time.Now()

	// Also persist to disk so it survives restart
	data, _ := json.Marshal(deduped)
	tmpPath := filepath.Join(s.path, "latest_findings.json.tmp")
	_ = os.WriteFile(tmpPath, data, 0600)
	_ = os.Rename(tmpPath, filepath.Join(s.path, "latest_findings.json"))
}

// LatestFindings returns the full results of the most recent scan.
// This is what the Findings page shows — "what's wrong right now."
func (s *Store) LatestFindings() []alert.Finding {
	s.latestMu.RLock()
	defer s.latestMu.RUnlock()

	// If in-memory is empty (fresh start), load from disk
	if len(s.latestFindings) == 0 {
		data, err := os.ReadFile(filepath.Join(s.path, "latest_findings.json"))
		if err == nil {
			var findings []alert.Finding
			if json.Unmarshal(data, &findings) == nil {
				s.latestMu.RUnlock()
				s.latestMu.Lock()
				s.latestFindings = findings
				s.latestMu.Unlock()
				s.latestMu.RLock()
				return findings
			}
		}
	}

	// Return a copy
	result := make([]alert.Finding, len(s.latestFindings))
	copy(result, s.latestFindings)
	return result
}

// LatestScanTime returns when the last scan completed.
func (s *Store) LatestScanTime() time.Time {
	s.latestMu.RLock()
	defer s.latestMu.RUnlock()
	return s.latestScanTime
}

// DismissLatestFinding removes a finding from the latest scan results.
func (s *Store) DismissLatestFinding(key string) {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()
	var filtered []alert.Finding
	for _, f := range s.latestFindings {
		if f.Check+":"+f.Message != key {
			filtered = append(filtered, f)
		}
	}
	s.latestFindings = filtered
}

// DismissFinding marks a finding as baseline (acknowledged/dismissed).
// It will no longer appear in active findings or trigger new alerts.
func (s *Store) DismissFinding(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, exists := s.entries[key]; exists {
		entry.IsBaseline = true
		s.dirty = true
	}
}

// ParseKey splits a state key "check:message" into its components.
func ParseKey(key string) (check, message string) {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}
