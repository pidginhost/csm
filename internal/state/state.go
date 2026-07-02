package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/atomicio"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/store"
)

// findingsTotal counts every finding CSM records, partitioned by
// severity. Registered lazily (via sync.Once) the first time a finding
// lands so tests that open Stores without running a full daemon do not
// panic on duplicate registration.
var (
	findingsTotal     *metrics.CounterVec
	findingsTotalOnce sync.Once
)

func ensureFindingsMetric() {
	findingsTotalOnce.Do(func() {
		findingsTotal = metrics.NewCounterVec(
			"csm_findings_total",
			"Findings recorded by CSM, partitioned by severity.",
			[]string{"severity"},
		)
		metrics.MustRegister("csm_findings_total", findingsTotal)
	})
}

func recordFindings(findings []alert.Finding) {
	if len(findings) == 0 {
		return
	}
	ensureFindingsMetric()
	for _, f := range findings {
		findingsTotal.With(f.Severity.String()).Inc()
	}
}

type Store struct {
	mu        sync.RWMutex
	path      string
	entries   map[string]*Entry
	dirty     bool   // true if state changed since last save
	savedHash string // hash of last saved state

	// LatestFindings holds the full output of the most recent scan cycle.
	// This is what the Findings page shows - "what's wrong right now" -
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
	// #nosec G304 -- operator-configured statePath + fixed filename.
	data, err := os.ReadFile(stateFile)
	if err == nil {
		// Backup state file before loading in case of corruption
		// #nosec G703 -- stateFile is filepath.Join(path, "state.json") where
		// path is the operator-configured statePath from csm.yaml.
		_ = os.WriteFile(stateFile+".bak", data, 0600)
		if unmarshalErr := json.Unmarshal(data, &s.entries); unmarshalErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse %s: %v (backup saved to %s.bak)\n", stateFile, unmarshalErr, stateFile)
		}
	}

	// Load latest findings from disk (survives restart)
	latestFile := filepath.Join(path, "latest_findings.json")
	// #nosec G304 -- operator-configured statePath + fixed filename.
	if latestData, err := os.ReadFile(latestFile); err == nil {
		// Backup latest findings before loading
		// #nosec G703 -- latestFile derived the same way as stateFile above.
		_ = os.WriteFile(latestFile+".bak", latestData, 0600)
		var findings []alert.Finding
		if unmarshalErr := json.Unmarshal(latestData, &findings); unmarshalErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse %s: %v (backup saved to %s.bak)\n", latestFile, unmarshalErr, latestFile)
		} else {
			s.latestFindings = findings
		}
	}

	return s, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
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

	// Atomic write with fsync. Power loss between rename and a dir
	// fsync can otherwise leave the file truncated; the savedHash gate
	// above then "skips" the next attempt because the in-memory hash is
	// unchanged, so corruption persists across restarts.
	stateFile := filepath.Join(s.path, "state.json")
	if err := atomicio.AtomicWriteJSON(stateFile, 0o600, s.entries); err != nil {
		return err
	}

	s.savedHash = newHash
	s.dirty = false
	return nil
}

func findingKey(f alert.Finding) string {
	return f.Key()
}

func findingHash(f alert.Finding) string {
	return f.Fingerprint()
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

	// Clean up entries that are no longer found. Keys with a leading
	// underscore are internal housekeeping written via SetRaw (throttles,
	// per-file content-hash baselines, sentinel flags) and never appear in
	// the findings stream, so the !seen branch would always evict them and
	// silently re-arm one-shot detectors that gate on their presence.
	for key, entry := range s.entries {
		if strings.HasPrefix(key, "_") {
			continue
		}
		if !seen[key] && !entry.IsBaseline {
			if time.Since(entry.LastSeen) > 24*time.Hour {
				delete(s.entries, key)
			}
		}
	}

	if err := s.save(); err != nil {
		fmt.Fprintf(os.Stderr, "state: error saving after update: %v\n", err)
	}
}

// MarkAlerted refreshes AlertSent on each finding's entry so the 24-hour
// dedup window restarts. Call after dispatch with the slice that came back
// from FilterNew. Without this, any finding that survives past the 24-hour
// expiry branch in FilterNew re-emits on every subsequent tick because
// Update only sets AlertSent when an entry is first created.
func (s *Store) MarkAlerted(findings []alert.Finding) {
	if len(findings) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	changed := false
	for _, f := range findings {
		key := findingKey(f)
		if entry, ok := s.entries[key]; ok {
			entry.AlertSent = now
			changed = true
		}
	}
	if !changed {
		return
	}
	s.dirty = true
	if err := s.save(); err != nil {
		fmt.Fprintf(os.Stderr, "state: error saving after MarkAlerted: %v\n", err)
	}
}

func (s *Store) SetBaseline(findings []alert.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = true
	var baselineAt *Entry
	if entry, ok := s.entries[baselineAtMetaKey]; ok {
		entryCopy := *entry
		baselineAt = &entryCopy
	}
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
	if baselineAt != nil {
		s.entries[baselineAtMetaKey] = baselineAt
	}

	if err := s.save(); err != nil {
		fmt.Fprintf(os.Stderr, "state: error saving baseline: %v\n", err)
	}
}

// ShouldRunThrottled reports whether the throttle window for checkName has
// elapsed, consuming the slot when it allows. Use only when the throttled
// work cannot fail or time out after scheduling; otherwise pair the
// read-only ThrottleAllows probe with MarkThrottledRan on completion so a
// failed run does not forfeit its slot.
func (s *Store) ShouldRunThrottled(checkName string, intervalMin int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := throttleKey(checkName)
	entry, exists := s.entries[key]
	if !exists {
		s.entries[key] = &Entry{LastSeen: time.Now()}
		s.dirty = true
		return true
	}
	if time.Since(entry.LastSeen) >= time.Duration(intervalMin)*time.Minute {
		entry.LastSeen = time.Now()
		s.dirty = true
		return true
	}
	return false
}

// ThrottleAllows reports whether the throttle window for checkName has
// elapsed WITHOUT consuming the slot. Callers stamp the slot with
// MarkThrottledRan only after the work completes, so a check that times
// out keeps its slot and may retry on the next cycle instead of waiting
// out the full window with nothing stored.
func (s *Store) ThrottleAllows(checkName string, intervalMin int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, exists := s.entries[throttleKey(checkName)]
	if !exists {
		return true
	}
	return time.Since(entry.LastSeen) >= time.Duration(intervalMin)*time.Minute
}

// MarkThrottledRan stamps the throttle slot for checkName. Call only after
// the throttled work actually completed, never at scheduling time.
func (s *Store) MarkThrottledRan(checkName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := throttleKey(checkName)
	if entry, exists := s.entries[key]; exists {
		entry.LastSeen = time.Now()
	} else {
		s.entries[key] = &Entry{LastSeen: time.Now()}
	}
	s.dirty = true
}

func throttleKey(checkName string) string {
	return "_throttle:" + checkName
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
	s.setRawLocked(key, value)
}

// SetRawAndSave stores a raw housekeeping value and immediately persists the
// state file. Use it for cursors where a completed scan must survive restart
// even when no finding is emitted later in the cycle.
func (s *Store) SetRawAndSave(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := s.setRawLocked(key, value)
	if !changed && !s.dirty {
		return nil
	}
	return s.save()
}

func (s *Store) setRawLocked(key, value string) bool {
	entry, exists := s.entries[key]
	if !exists {
		s.entries[key] = &Entry{
			Hash:      value,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		s.dirty = true
		return true
	}
	if entry.Hash != value {
		entry.Hash = value
		entry.LastSeen = time.Now()
		s.dirty = true
		return true
	}
	return false
}

// AppendHistory writes findings to the bbolt store (if available) or
// falls back to the append-only JSONL history file.
// The JSONL fallback is deprecated and will be removed in a future release.
func (s *Store) AppendHistory(findings []alert.Finding) {
	if len(findings) == 0 {
		return
	}

	recordFindings(findings)

	// Use bbolt store when available; skip JSONL writes entirely.
	if db := store.Global(); db != nil {
		if err := db.AppendHistory(findings); err != nil {
			fmt.Fprintf(os.Stderr, "store: append history: %v\n", err)
		}
		return
	}

	// Deprecated: flat-file JSONL fallback has a truncation race condition.
	// This path is kept only for installations that have not yet migrated to bbolt.
	fmt.Fprintf(os.Stderr, "DEPRECATION: using JSONL history fallback; migrate to bbolt store\n")
	s.appendHistoryFile(findings)
}

// appendHistoryFile writes findings to the append-only JSONL history file.
// Caps file at 10MB by truncating the oldest half.
func (s *Store) appendHistoryFile(findings []alert.Finding) {
	histPath := filepath.Join(s.path, "history.jsonl")

	// Check size, truncate if over 10MB
	if info, err := os.Stat(histPath); err == nil && info.Size() > 10*1024*1024 {
		// #nosec G304 -- histPath is {s.path}/history.jsonl; s.path is the
		// operator-configured statePath set at Store creation.
		data, err := os.ReadFile(histPath)
		if err == nil {
			// Keep the second half
			half := len(data) / 2
			for half < len(data) && data[half] != '\n' {
				half++
			}
			if half < len(data) {
				// #nosec G703 -- histPath comes from state.historyPath, a
				// filepath.Join under the operator-configured statePath.
				_ = os.WriteFile(histPath, data[half+1:], 0600)
			}
		}
	}

	// #nosec G304 -- see histPath derivation above.
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

// ReadHistory reads the last limit entries, starting at offset.
// Returns the findings (newest first) and total count.
// Uses bbolt store when available, falls back to flat-file JSONL.
func (s *Store) ReadHistory(limit, offset int) ([]alert.Finding, int) {
	// Use bbolt store when available.
	if db := store.Global(); db != nil {
		return db.ReadHistory(limit, offset)
	}

	// Fallback: flat-file JSONL.
	historyPath := filepath.Join(s.path, "history.jsonl")
	// #nosec G304 -- {s.path}/history.jsonl; s.path from operator config.
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

// ReadHistoryFiltered reads matching history entries newest-first.
// Date strings that are not YYYY-MM-DD are ignored before they reach the
// lexicographic bbolt key filter.
func (s *Store) ReadHistoryFiltered(limit, offset int, from, to string, severity int, search string) ([]alert.Finding, int) {
	return s.ReadHistoryFilteredWithChecks(limit, offset, from, to, severity, search, nil)
}

// ReadHistoryFilteredWithChecks reads matching history entries newest-first,
// optionally constrained to an exact check-name set.
func (s *Store) ReadHistoryFilteredWithChecks(
	limit, offset int,
	from, to string,
	severity int,
	search string,
	checks map[string]bool,
) ([]alert.Finding, int) {
	var fromDate, toDate time.Time
	fromFilter := ""
	toFilter := ""
	if from != "" {
		if t, err := time.ParseInLocation("2006-01-02", from, time.Local); err == nil {
			fromDate = t
			fromFilter = from
		}
	}
	if to != "" {
		if t, err := time.ParseInLocation("2006-01-02", to, time.Local); err == nil {
			toDate = t.Add(24*time.Hour - time.Nanosecond)
			toFilter = to
		}
	}

	if db := store.Global(); db != nil {
		return db.ReadHistoryFilteredWithChecks(limit, offset, fromFilter, toFilter, severity, search, checks)
	}

	all, _ := s.ReadHistory(1<<30, 0)
	searchLower := strings.ToLower(search)
	var results []alert.Finding
	matched := 0
	for _, f := range all {
		if !fromDate.IsZero() && f.Timestamp.Before(fromDate) {
			continue
		}
		if !toDate.IsZero() && f.Timestamp.After(toDate) {
			continue
		}
		if severity >= 0 && int(f.Severity) != severity {
			continue
		}
		if checks != nil && !checks[f.Check] {
			continue
		}
		if search != "" {
			if !strings.Contains(strings.ToLower(f.Check), searchLower) &&
				!strings.Contains(strings.ToLower(f.Message), searchLower) &&
				!strings.Contains(strings.ToLower(f.Details), searchLower) {
				continue
			}
		}
		matched++
		if matched > offset && len(results) < limit {
			results = append(results, f)
		}
	}
	return results, matched
}

// ReadHistorySince returns all findings since the given time.
// Uses bbolt cursor seeking for efficiency. Results are newest-first.
// Falls back to the JSONL store with a linear cutoff filter when bbolt
// is unavailable so test wiring and migration-pending hosts still get
// time-bounded search results.
func (s *Store) ReadHistorySince(since time.Time) []alert.Finding {
	if db := store.Global(); db != nil {
		return db.ReadHistorySince(since)
	}
	all, _ := s.ReadHistory(1<<30, 0)
	out := all[:0]
	for _, f := range all {
		if !f.Timestamp.Before(since) {
			out = append(out, f)
		}
	}
	return out
}

// SearchHistorySince returns up to limit matching findings since the given
// time, newest-first.
func (s *Store) SearchHistorySince(since time.Time, limit int, match func(alert.Finding) bool) []alert.Finding {
	if limit <= 0 {
		return nil
	}
	if db := store.Global(); db != nil {
		return db.SearchHistorySince(since, limit, match)
	}
	return s.searchHistoryFileSince(since, limit, match)
}

func (s *Store) searchHistoryFileSince(since time.Time, limit int, match func(alert.Finding) bool) []alert.Finding {
	historyPath := filepath.Join(s.path, "history.jsonl")
	// #nosec G304 -- {s.path}/history.jsonl; s.path from operator config.
	data, err := os.ReadFile(historyPath)
	if err != nil {
		return nil
	}

	var results []alert.Finding
	end := len(data)
	for end > 0 && len(results) < limit {
		for end > 0 && (data[end-1] == '\n' || data[end-1] == '\r') {
			end--
		}
		if end == 0 {
			break
		}

		start := bytes.LastIndexByte(data[:end], '\n') + 1
		line := data[start:end]
		if start == 0 {
			end = 0
		} else {
			end = start - 1
		}

		var f alert.Finding
		if err := json.Unmarshal(line, &f); err != nil {
			continue
		}
		// The JSONL fallback appends findings in chronological order, so
		// once a reverse scan reaches an old row the remaining rows are older.
		if f.Timestamp.Before(since) {
			break
		}
		if match != nil && !match(f) {
			continue
		}
		results = append(results, f)
	}
	return results
}

// AggregateByHour returns 24 hourly severity buckets for the last 24 hours.
func (s *Store) AggregateByHour() []store.HourBucket {
	if db := store.Global(); db != nil {
		return db.AggregateByHour()
	}
	return nil
}

// AggregateByDay returns 30 daily severity buckets for the last 30 days.
func (s *Store) AggregateByDay() []store.DayBucket {
	if db := store.Global(); db != nil {
		return db.AggregateByDay()
	}
	return nil
}

// AggregateByDayN returns `days` daily severity buckets (oldest first),
// clamped by the underlying store's retention window.
func (s *Store) AggregateByDayN(days int) []store.DayBucket {
	if db := store.Global(); db != nil {
		return db.AggregateByDayN(days)
	}
	return nil
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
// than replaces - critical scan results coexist with deep scan results.
// Use ClearLatestFindings() + SetLatestFindings() for a full replace.
func (s *Store) SetLatestFindings(findings []alert.Finding) {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()

	// Build map of existing findings by key
	existing := make(map[string]alert.Finding)
	for _, f := range s.latestFindings {
		existing[f.Key()] = f
	}

	// Merge new findings (update existing, add new)
	for _, f := range findings {
		existing[f.Key()] = f // newer overwrites older
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
	_ = atomicio.AtomicWriteJSON(filepath.Join(s.path, "latest_findings.json"), 0o600, merged)
}

// PurgeFindingsByChecks removes all findings whose Check field matches
// any of the given check names and persists the result to disk.
// Used to clear stale performance findings before merging fresh results
// from a scan tier.
func (s *Store) PurgeFindingsByChecks(checks []string) {
	if len(checks) == 0 {
		return
	}
	s.latestMu.Lock()
	defer s.latestMu.Unlock()

	remove := make(map[string]bool, len(checks))
	for _, c := range checks {
		remove[c] = true
	}

	n := 0
	for _, f := range s.latestFindings {
		if !remove[f.Check] {
			s.latestFindings[n] = f
			n++
		}
	}
	s.latestFindings = s.latestFindings[:n]

	// Persist to disk so purged findings don't reappear after restart.
	// Mirrors the persistence logic at the end of SetLatestFindings().
	_ = atomicio.AtomicWriteJSON(filepath.Join(s.path, "latest_findings.json"), 0o600, s.latestFindings)
}

// PurgeAndMergeFindings atomically removes findings matching the given check
// names and then merges the new findings. This prevents a race window where
// concurrent readers could see findings with perf checks missing.
func (s *Store) PurgeAndMergeFindings(purgeChecks []string, findings []alert.Finding) {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()

	// Build set of checks to purge
	remove := make(map[string]bool, len(purgeChecks))
	for _, c := range purgeChecks {
		remove[c] = true
	}

	// Build map: keep existing non-purged findings
	existing := make(map[string]alert.Finding)
	for _, f := range s.latestFindings {
		if !shouldPurgeLatestFinding(f, remove) {
			existing[f.Key()] = f
		}
	}

	// Merge new findings
	for _, f := range findings {
		existing[f.Key()] = f
	}

	// Flatten
	var merged []alert.Finding
	for _, f := range existing {
		merged = append(merged, f)
	}
	if len(merged) > 15000 {
		merged = merged[:15000]
	}
	s.latestFindings = merged
	s.latestScanTime = time.Now()

	// Persist
	_ = atomicio.AtomicWriteJSON(filepath.Join(s.path, "latest_findings.json"), 0o600, merged)
}

func shouldPurgeLatestFinding(f alert.Finding, remove map[string]bool) bool {
	if remove[f.Check] {
		return true
	}
	if f.Check != "check_timeout" {
		return false
	}
	runner, ok := timeoutFindingRunner(f.Message)
	return ok && remove[runner]
}

func timeoutFindingRunner(msg string) (string, bool) {
	rest, ok := strings.CutPrefix(msg, "Check '")
	if !ok {
		return "", false
	}
	runner, _, ok := strings.Cut(rest, "'")
	return runner, ok && runner != ""
}

// ClearLatestFindings removes all findings from the latest set.
// Use before SetLatestFindings for a full replace (e.g. initial scan).
func (s *Store) ClearLatestFindings() {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()
	s.latestFindings = nil
}

// LatestFindings returns the full results of the most recent scan.
// This is what the Findings page shows - "what's wrong right now."
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

const baselineAtMetaKey = "__baseline_at"

// EnsureBaseline records the first-start timestamp the first time it is
// called against a fresh state directory. Subsequent calls preserve the
// original value so reinstalls / upgrades do not reset the baseline. Safe
// to call from the daemon boot path on every start.
func (s *Store) EnsureBaseline(now time.Time) {
	if _, ok := s.GetRaw(baselineAtMetaKey); ok {
		return
	}
	s.SetRaw(baselineAtMetaKey, now.UTC().Format(time.RFC3339Nano))
}

// BaselineAt returns the persisted baseline timestamp, or the zero time
// when EnsureBaseline has not been called yet.
func (s *Store) BaselineAt() time.Time {
	raw, ok := s.GetRaw(baselineAtMetaKey)
	if !ok {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return t
}

// DismissLatestFinding removes a finding from the latest scan results.
func (s *Store) DismissLatestFinding(key string) {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()
	var filtered []alert.Finding
	for _, f := range s.latestFindings {
		if f.Key() != key {
			filtered = append(filtered, f)
		}
	}
	s.latestFindings = filtered
	_ = atomicio.AtomicWriteJSON(filepath.Join(s.path, "latest_findings.json"), 0o600, s.latestFindings)
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

// SaveSuppressions writes suppression rules to disk atomically with fsync.
func (s *Store) SaveSuppressions(rules []SuppressionRule) error {
	return atomicio.AtomicWriteJSON(filepath.Join(s.path, "suppressions.json"), 0o600, rules)
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
		for _, candidate := range suppressionPathCandidates(f) {
			if matched, _ := filepath.Match(rule.PathPattern, candidate); matched {
				return true
			}
		}
	}
	return false
}

func suppressionPathCandidates(f alert.Finding) []string {
	if f.FilePath != "" {
		return []string{f.FilePath}
	}

	fields := strings.Fields(f.Message + " " + f.Details)
	seen := make(map[string]bool)
	var paths []string
	for _, field := range fields {
		field = strings.Trim(field, `"'():,;[]{}<>`)
		if !strings.HasPrefix(field, "/") {
			continue
		}
		candidate := filepath.Clean(field)
		if candidate == "." || candidate == "/" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		paths = append(paths, candidate)
	}
	return paths
}
