package state

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	// Load latest findings from disk (survives restart)
	latestFile := filepath.Join(path, "latest_findings.json")
	if latestData, err := os.ReadFile(latestFile); err == nil {
		var findings []alert.Finding
		if json.Unmarshal(latestData, &findings) == nil {
			s.latestFindings = findings
		}
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

// EntryForKey returns the dedup entry for a finding key (check:message).
func (s *Store) EntryForKey(key string) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[key]
	if !ok {
		return Entry{}, false
	}
	return *e, true
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

// SetLatestFindings merges scan results into the current findings set.
// Called by the daemon after each periodic scan completes. Merges rather
// than replaces — critical scan results coexist with deep scan results.
// Use ClearLatestFindings() + SetLatestFindings() for a full replace.
func (s *Store) SetLatestFindings(findings []alert.Finding) {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()

	// Build map of existing findings by key
	existing := make(map[string]alert.Finding)
	for _, f := range s.latestFindings {
		key := f.Check + ":" + f.Message
		existing[key] = f
	}

	// Merge new findings (update existing, add new)
	for _, f := range findings {
		key := f.Check + ":" + f.Message
		existing[key] = f // newer overwrites older
	}

	// Flatten back to slice
	var merged []alert.Finding
	for _, f := range existing {
		merged = append(merged, f)
	}
	// Cap at 15,000 findings to prevent unbounded memory growth
	if len(merged) > 15000 {
		merged = merged[:15000]
	}
	s.latestFindings = merged
	s.latestScanTime = time.Now()

	// Persist to disk
	data, _ := json.Marshal(merged)
	tmpPath := filepath.Join(s.path, "latest_findings.json.tmp")
	_ = os.WriteFile(tmpPath, data, 0600)
	_ = os.Rename(tmpPath, filepath.Join(s.path, "latest_findings.json"))
}

// ClearLatestFindings removes all findings from the latest set.
// Use before SetLatestFindings for a full replace (e.g. initial scan).
func (s *Store) ClearLatestFindings() {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()
	s.latestFindings = nil
}

// LatestFindings returns the full results of the most recent scan.
// This is what the Findings page shows — "what's wrong right now."
func (s *Store) LatestFindings() []alert.Finding {
	s.latestMu.RLock()
	defer s.latestMu.RUnlock()
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

// --- Suppression rules ---

// SuppressionRule defines a rule for suppressing specific findings.
type SuppressionRule struct {
	ID          string    `json:"id"`
	Check       string    `json:"check"`
	PathPattern string    `json:"path_pattern,omitempty"`
	Reason      string    `json:"reason"`
	CreatedAt   time.Time `json:"created_at"`
}

// LoadSuppressions reads suppression rules from disk.
func (s *Store) LoadSuppressions() []SuppressionRule {
	data, err := os.ReadFile(filepath.Join(s.path, "suppressions.json"))
	if err != nil {
		return nil
	}
	var rules []SuppressionRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil
	}
	return rules
}

// SaveSuppressions writes suppression rules to disk atomically.
func (s *Store) SaveSuppressions(rules []SuppressionRule) error {
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	target := filepath.Join(s.path, "suppressions.json")
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// IsSuppressed checks if a finding matches any loaded suppression rule.
// Load rules once with LoadSuppressions() and pass them in to avoid
// re-reading the file for every finding.
func (s *Store) IsSuppressed(f alert.Finding, rules []SuppressionRule) bool {
	for _, rule := range rules {
		if f.Check != rule.Check {
			continue
		}
		// If no path pattern, suppress all findings for this check type
		if rule.PathPattern == "" {
			return true
		}
		// Match against the finding's FilePath
		if f.FilePath != "" {
			if matched, _ := filepath.Match(rule.PathPattern, f.FilePath); matched {
				return true
			}
		}
		// Match against paths embedded in the message
		if strings.Contains(f.Message, "/") {
			if matched, _ := filepath.Match(rule.PathPattern, f.Message); matched {
				return true
			}
		}
	}
	return false
}
