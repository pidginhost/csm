package state

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/atomicio"
	"github.com/pidginhost/csm/internal/config"
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
	mu                   sync.RWMutex
	path                 string
	entries              map[string]*Entry
	dirty                bool             // true if state changed since last save
	savedHash            string           // hash of last saved state
	lastSave             time.Time        // start of the last save attempt
	now                  func() time.Time // save clock; nil means time.Now
	throttleReservations map[string]struct{}
	emailPending         map[string]*Entry

	pendingHealthOnce sync.Once
	pendingQueue      *pendingQueue
	readPendingFile   func(string) ([]byte, error)
	writePendingFile  func(string, os.FileMode, any) error

	// LatestFindings holds the full output of the most recent scan cycle.
	// This is what the Findings page shows - "what's wrong right now" -
	// separate from the alert dedup state above which controls "what to email."
	latestMu        sync.RWMutex
	latestFindings  []alert.Finding
	latestDigest    [sha256.Size]byte // digest of the last persisted latest_findings.json
	latestDigestSet bool
	latestScanTime  time.Time

	// suppressMu makes each change to the suppression rules one
	// read-modify-write, so concurrent edits do not overwrite each other.
	suppressMu sync.Mutex
}

type Entry struct {
	// observation changes only when Update records evidence, not when an email completes.
	observation uint64

	Hash        string    `json:"hash"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	AlertSent   time.Time `json:"alert_sent"`
	IsBaseline  bool      `json:"is_baseline"`
	DismissalID string    `json:"dismissal_id,omitempty"`
	// Emailed is the fingerprint alert email or the generic webhook last
	// delivered under this key. Hash follows every observation; Emailed
	// changes only on delivery.
	Emailed string `json:"emailed,omitempty"`
	// KeptAt is when the latest-findings merge last kept the condition
	// listed without a new report, as for a check that skipped its run.
	// LastSeen stays the last report, which the findings page shows.
	KeptAt time.Time `json:"kept_at,omitzero"`
	// ContentSHA256 is the file content a dismissal or baseline covers.
	ContentSHA256 string `json:"content_sha256,omitempty"`
	// Path is the file the finding names, so alert state about a file CSM
	// removed can be cleared.
	Path string `json:"path,omitempty"`
}

// aliveAt is the last time the condition was reported or kept listed. An
// entry older than 24h by this measure has cleared.
func (e *Entry) aliveAt() time.Time {
	if e.KeptAt.After(e.LastSeen) {
		return e.KeptAt
	}
	return e.LastSeen
}

// lapsingAcknowledgments names the checks whose explicit identity is an event
// condition, reported for as long as it lasts. An acknowledgment of one
// covers later reports only until the condition clears. Scan findings keep
// permanent acknowledgments: a producer that reports once a day or less would
// otherwise lose the dismissal on every cycle.
var lapsingAcknowledgments = map[string]bool{
	"auto_block":                     true,
	"email_av_degraded":              true,
	"self_deleting_dropper_realtime": true,
	"sensitive_file_modified":        true,
	"smtp_probe_abuse":               true,
}

// permanent reports a baseline or dismissal that never lapses.
func (e *Entry) permanent(key string) bool {
	if !e.IsBaseline {
		return false
	}
	identity, explicit := strings.CutPrefix(key, "dedup:")
	check, _, _ := strings.Cut(identity, ":")
	return !explicit || !lapsingAcknowledgments[check]
}

// cleared reports whether the condition behind an entry that can lapse has
// gone unseen for 24h.
func (e *Entry) cleared(key string, now time.Time) bool {
	return !e.permanent(key) && now.Sub(e.aliveAt()) >= 24*time.Hour
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, fmt.Errorf("creating state dir: %w", err)
	}

	s := &Store{
		path:                 path,
		entries:              make(map[string]*Entry),
		throttleReservations: make(map[string]struct{}),
	}

	stateFile := filepath.Join(path, "state.json")
	loadJSONWithBackup(stateFile, &s.entries)
	if s.entries == nil {
		s.entries = make(map[string]*Entry)
	}
	s.migrateEmailGate()

	// Load latest findings from disk (survives restart)
	latestFile := filepath.Join(path, "latest_findings.json")
	var findings []alert.Finding
	if loadJSONWithBackup(latestFile, &findings) {
		s.latestFindings = findings
	}

	s.observePendingQueue()
	return s, nil
}

// loadJSONWithBackup parses file into v. The backup copy is refreshed only
// after a successful parse, so a corrupt file can never overwrite the last
// good one; on a parse failure the backup is parsed instead. Copying the
// file over its backup before parsing, as this used to, destroyed the
// backup exactly when it was needed and silently reset the alert dedup
// state, re-alerting every known finding. Returns true when v was loaded
// from either source.
func loadJSONWithBackup(file string, v any) bool {
	bakFile := file + ".bak"
	// #nosec G304 -- operator-configured statePath + fixed filename.
	data, err := os.ReadFile(file)
	if err == nil {
		if unmarshalErr := json.Unmarshal(data, v); unmarshalErr == nil {
			// Refresh atomically so a crash while copying a good primary cannot
			// destroy the last usable backup.
			_ = atomicio.AtomicWrite(bakFile, 0o600, data)
			return true
		} else {
			fmt.Fprintf(os.Stderr, "warning: failed to parse %s: %v (trying %s)\n", file, unmarshalErr, bakFile)
		}
	}
	// #nosec G304 -- same fixed name with a .bak suffix.
	bak, err := os.ReadFile(bakFile)
	if err != nil {
		return false
	}
	if unmarshalErr := json.Unmarshal(bak, v); unmarshalErr != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to parse %s: %v\n", bakFile, unmarshalErr)
		return false
	}
	fmt.Fprintf(os.Stderr, "warning: restored %s from %s\n", file, bakFile)
	return true
}

// stateFileWriter writes state.json; a seam for tests.
var stateFileWriter = atomicio.AtomicWrite

// saveInterval bounds how often Update and MarkAlerted rewrite state.json.
// They run on every alert batch and the file holds the whole dedup map, so
// saving on each batch would rewrite it several times a minute on a busy
// host. FlushDue, Flush and Close write what they leave pending.
const saveInterval = 60 * time.Second

func (s *Store) clock() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

// FlushDue writes pending changes once saveInterval has passed since the
// last save. Call it periodically so the last batch before a quiet spell
// still reaches disk.
func (s *Store) FlushDue(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty || now.Sub(s.lastSave) < saveInterval {
		return nil
	}
	return s.save()
}

// Flush writes pending changes now.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.save()
}

func (s *Store) Close() error {
	return s.Flush()
}

func (s *Store) save() error {
	// Even a fresh or reset store can persist observations before its first
	// successful delivery. They must never be mistaken for pre-gate state.
	s.setRawLocked(emailGateMetaKey, "1")
	// A failed write counts too: a full disk is retried once per
	// saveInterval, not on every alert batch.
	s.lastSave = s.clock()
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
	// Older releases wrote through a fixed <path>.tmp; clear one left by a
	// crash so it cannot be mistaken for live state.
	if err := os.Remove(stateFile + ".tmp"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale tmp: %w", err)
	}
	if err := stateFileWriter(stateFile, 0o600, data); err != nil {
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
	now := s.clock()

	for _, f := range findings {
		key := findingKey(f)
		hash := findingHash(f)

		entry, exists := s.entries[key]
		if !exists || entry.cleared(key, now) {
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

// emailGateMetaKey marks alert state whose entries record email delivery.
const emailGateMetaKey = "__email_gate"

// migrateEmailGate treats every condition alerted before the email gate
// existed as delivered, muted and cap-held ones included. Without it an
// upgrade would email every known condition at once. Every save writes the
// marker, so state from a gated build never migrates, and a fresh store has
// nothing to migrate.
func (s *Store) migrateEmailGate() {
	if len(s.entries) == 0 {
		return
	}
	if _, ok := s.entries[emailGateMetaKey]; ok {
		return
	}
	for key, entry := range s.entries {
		if !entry.AlertSent.IsZero() && !entry.IsBaseline && !strings.HasPrefix(key, "_") {
			entry.Emailed = entry.Hash
		}
	}
	s.setRawLocked(emailGateMetaKey, "1")
}

// filterUnemailedLocked returns the findings alert email and the generic
// webhook have not delivered with their current content. Unlike FilterNew it
// has no daily reminder: a finding is offered again when its content changes,
// when a covering scan cleared it, or when it was neither reported nor kept
// listed for 24h. An entry that old is deleted here, so a return needs no
// Update sweep first. Held findings refresh LastSeen, so an action or derived
// finding that never reaches Update keeps its receipt while it is still
// produced.
func (s *Store) filterUnemailedLocked(findings []alert.Finding, now time.Time) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		hash := findingHash(f)
		key := findingKey(f)
		entry, ok := s.entries[key]
		if ok && entry.cleared(key, now) {
			delete(s.entries, key)
			s.dirty = true
			ok = false
		}
		held := ok && (entry.Emailed == hash || (entry.IsBaseline && entry.Hash == hash))
		if !held {
			out = append(out, f)
			continue
		}
		entry.LastSeen = now
		s.dirty = true
	}
	return out
}

// MarkKept records that the latest-findings merge kept these keys listed. An
// owner that skips or does not finish a run keeps its rows without reporting
// them, and a listed condition must not count as cleared after 24h, neither
// for the email gate nor for the Update sweep. An entry already 24h stale is
// not revived: after downtime the next report emails once.
func (s *Store) MarkKept(keys []string) {
	if len(keys) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	for _, key := range keys {
		entry, ok := s.entries[key]
		// Permanent baselines need no liveness, so retaining them writes nothing.
		if !ok || entry.permanent(key) || entry.cleared(key, now) {
			continue
		}
		entry.KeptAt = now
		s.dirty = true
	}
}

// ForgetCleared deletes the alert state of findings a covering scan no longer
// reports, so a return is new again. Dismissals and internal keys stay.
func (s *Store) ForgetCleared(findings []alert.Finding) {
	if len(findings) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range findings {
		key := findingKey(f)
		if strings.HasPrefix(key, "_") {
			continue
		}
		if entry, ok := s.entries[key]; ok && !entry.IsBaseline {
			delete(s.entries, key)
			s.dirty = true
		}
	}
}

// ReconcileDismissedContent ends a dismissal or baseline once its finding
// reports different file content, and records the content of one that has
// none yet (a dismissal from before content was recorded, or made while the
// hash was unknown). It must run before FilterNew and delivery see the batch.
// The entry is deleted rather than un-dismissed so no AlertSent or Emailed
// receipt survives: the changed file alerts as a new detection. A finding
// without a content hash, or carried from an unexamined path, proves nothing
// and changes nothing. The returned batch keeps, for an ended dismissal, only
// the observations of new content, so deduplication alerts on those.
func (s *Store) ReconcileDismissedContent(findings []alert.Finding) []alert.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ended map[string]string
	for _, f := range findings {
		if f.ContentSHA256 == "" || f.ScanCarryForward {
			continue
		}
		key := findingKey(f)
		if strings.HasPrefix(key, "_") {
			continue
		}
		entry, ok := s.entries[key]
		if !ok || !entry.IsBaseline || entry.ContentSHA256 == f.ContentSHA256 {
			continue
		}
		if entry.ContentSHA256 == "" {
			entry.ContentSHA256 = f.ContentSHA256
		} else {
			if ended == nil {
				ended = make(map[string]string)
			}
			ended[key] = entry.ContentSHA256
			delete(s.entries, key)
			fmt.Fprintf(os.Stderr, "state: content changed, dismissal ended: %s\n", key)
		}
		s.dirty = true
	}
	if ended == nil {
		return findings
	}
	kept := make([]alert.Finding, 0, len(findings))
	for _, f := range findings {
		if old, ok := ended[findingKey(f)]; ok && (f.ContentSHA256 == "" || f.ScanCarryForward || f.ContentSHA256 == old) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// ForgetFileAlerts deletes the alert state of every finding about path after
// CSM removed or cleaned that file, so a report of the file coming back is new
// again. Dismissals and internal keys stay.
func (s *Store) ForgetFileAlerts(path string) {
	if path == "" {
		return
	}
	path = filepath.Clean(path)
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, entry := range s.entries {
		if entry.Path != path || entry.IsBaseline || strings.HasPrefix(key, "_") {
			continue
		}
		delete(s.entries, key)
		s.dirty = true
	}
}

func (s *Store) Update(findings []alert.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = true
	now := s.clock()

	seen := make(map[string]bool)
	for _, f := range findings {
		key := findingKey(f)
		hash := findingHash(f)
		seen[key] = true

		entry, exists := s.entries[key]
		if exists && entry.cleared(key, now) {
			exists = false
		}
		if !exists {
			entry = &Entry{
				observation: 1,
				Hash:        hash,
				FirstSeen:   now,
				LastSeen:    now,
				AlertSent:   now,
			}
			s.entries[key] = entry
		} else {
			entry.observation++
			entry.Hash = hash
			entry.LastSeen = now
			if entry.AlertSent.IsZero() {
				entry.AlertSent = now
			}
		}
		if f.FilePath != "" {
			entry.Path = filepath.Clean(f.FilePath)
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
		if !seen[key] && entry.cleared(key, now) {
			delete(s.entries, key)
		}
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
	now := s.clock()
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
	previous := s.entries
	s.entries = make(map[string]*Entry)
	now := time.Now()

	for _, f := range findings {
		key := findingKey(f)
		hash := findingHash(f)
		content := f.ContentSHA256
		if content == "" {
			// Missing evidence must not erase known content, including when
			// another result in this baseline already supplied it.
			entry := s.entries[key]
			if entry == nil {
				entry = previous[key]
			}
			if entry != nil {
				content = entry.ContentSHA256
			}
		}
		s.entries[key] = &Entry{
			Hash:          hash,
			FirstSeen:     now,
			LastSeen:      now,
			IsBaseline:    true,
			ContentSHA256: content,
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

// ReserveThrottle reports whether the throttle window allows checkName to
// start now and reserves the slot for this process until the caller either
// marks the run complete or releases the reservation. The reservation keeps
// concurrent scans from launching the same expensive check before the first
// one has had a chance to stamp its successful run.
func (s *Store) ReserveThrottle(checkName string, intervalMin int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := throttleKey(checkName)
	s.ensureThrottleReservationsLocked()
	if _, running := s.throttleReservations[key]; running {
		return false
	}
	entry, exists := s.entries[key]
	if exists && time.Since(entry.LastSeen) < time.Duration(intervalMin)*time.Minute {
		return false
	}
	s.throttleReservations[key] = struct{}{}
	return true
}

// MarkThrottledRan stamps the throttle slot for checkName. Call only after
// the throttled work actually completed, never at scheduling time.
func (s *Store) MarkThrottledRan(checkName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := throttleKey(checkName)
	if s.throttleReservations != nil {
		delete(s.throttleReservations, key)
	}
	if entry, exists := s.entries[key]; exists {
		entry.LastSeen = time.Now()
	} else {
		s.entries[key] = &Entry{LastSeen: time.Now()}
	}
	s.dirty = true
}

// ReleaseThrottle clears an in-process throttle reservation without stamping
// a successful run. Use when the reserved work times out or is interrupted.
func (s *Store) ReleaseThrottle(checkName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.throttleReservations != nil {
		delete(s.throttleReservations, throttleKey(checkName))
	}
}

func (s *Store) ensureThrottleReservationsLocked() {
	if s.throttleReservations == nil {
		s.throttleReservations = make(map[string]struct{})
	}
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

// DeleteRaw drops a raw housekeeping entry. Underscore-prefixed keys are exempt
// from the sweeper, so a caller that no longer wants one has to say so.
func (s *Store) DeleteRaw(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteRawLocked(key)
}

// DeleteRawAndSave drops a raw housekeeping entry and persists the deletion
// before returning.
func (s *Store) DeleteRawAndSave(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := s.deleteRawLocked(key)
	if !changed && !s.dirty {
		return nil
	}
	return s.save()
}

func (s *Store) deleteRawLocked(key string) bool {
	if _, ok := s.entries[key]; !ok {
		return false
	}
	delete(s.entries, key)
	s.dirty = true
	return true
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

// ClaimRawTimestamp atomically claims a persisted time window. It returns
// true for the first claim and after interval has elapsed. A future stored
// timestamp can result from a backward wall-clock step; rebase it to now so
// the window does not stay suppressed until the old clock value catches up.
func (s *Store) ClaimRawTimestamp(key string, now time.Time, interval time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now = now.Round(0)
	if entry, ok := s.entries[key]; ok {
		if previous, err := time.Parse(time.RFC3339Nano, entry.Hash); err == nil {
			previous = previous.Round(0)
			if previous.After(now) {
				entry.Hash = now.Format(time.RFC3339Nano)
				entry.LastSeen = now
				s.dirty = true
				return false, s.save()
			}
			if now.Sub(previous) < interval {
				return false, nil
			}
		}
	}

	s.setRawLocked(key, now.Format(time.RFC3339Nano))
	return true, s.save()
}

func (s *Store) setRawLocked(key, value string) bool {
	if s.entries == nil {
		// A zero-value Store (tests, ad-hoc callers) must not panic on its
		// first write; it simply has nothing persisted yet.
		s.entries = make(map[string]*Entry)
	}
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

// AppendHistory writes findings to the state DB. Without an open DB the
// findings are not kept: the daemon refuses to start without one.
func (s *Store) AppendHistory(findings []alert.Finding) {
	if len(findings) == 0 {
		return
	}

	recordFindings(findings)

	if db := store.Global(); db != nil {
		if err := db.AppendHistory(findings); err != nil {
			fmt.Fprintf(os.Stderr, "store: append history: %v\n", err)
		}
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

// Acknowledged reports whether a baseline or dismissal still covers f.
func (s *Store) Acknowledged(f alert.Finding) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := findingKey(f)
	e, ok := s.entries[key]
	return ok && e.IsBaseline && e.Hash == findingHash(f) && !e.cleared(key, s.clock())
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
func (s *Store) ReadHistory(limit, offset int) ([]alert.Finding, int) {
	if db := store.Global(); db != nil {
		return db.ReadHistory(limit, offset)
	}
	return nil, 0
}

// ReadHistoryFiltered reads matching history entries newest-first.
// Bounds accept server-local calendar days or RFC 3339 instants. Invalid
// bounds are ignored before they reach the lexicographic bbolt key filter.
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
	// An unreadable bound is dropped; the web UI rejects one before it gets
	// here.
	fromFilter := ""
	toFilter := ""
	if _, err := store.ParseHistoryBound(from, false); err == nil {
		fromFilter = from
	}
	if _, err := store.ParseHistoryBound(to, true); err == nil {
		toFilter = to
	}

	if db := store.Global(); db != nil {
		return db.ReadHistoryFilteredWithChecks(limit, offset, fromFilter, toFilter, severity, search, checks)
	}
	return nil, 0
}

// ReadHistorySince returns all findings since the given time, newest-first.
func (s *Store) ReadHistorySince(since time.Time) []alert.Finding {
	if db := store.Global(); db != nil {
		return db.ReadHistorySince(since)
	}
	return nil
}

// HistoryMark changes whenever history does.
func (s *Store) HistoryMark() string {
	if db := store.Global(); db != nil {
		return db.HistoryMark()
	}
	return ""
}

// LatestByCheck returns the timestamp of the newest history entry of every
// check.
func (s *Store) LatestByCheck() map[string]time.Time {
	if db := store.Global(); db != nil {
		return db.LatestByCheck()
	}
	return map[string]time.Time{}
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
	return nil
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

	s.latestFindings = orderAndCapLatest(existing)
	s.latestScanTime = time.Now()
	s.persistLatestLocked()
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
	s.persistLatestLocked()
}

// PurgeAndMergeFindings atomically removes findings matching the given check
// names and then merges the new findings. This prevents a race window where
// concurrent readers could see findings with perf checks missing.
func (s *Store) PurgeAndMergeFindings(purgeChecks []string, findings []alert.Finding) {
	s.PurgeAndMergeFindingsDerived(purgeChecks, findings, nil, nil)
}

// PurgeAndMergeFindingsDerived is PurgeAndMergeFindings followed, under the
// same lock and before the single persist, by a second purge-and-merge of
// derivedChecks with derive(merged): the correlation findings a tier cycle
// rebuilds from the merged set. One file write per cycle instead of two.
func (s *Store) PurgeAndMergeFindingsDerived(purgeChecks []string, findings []alert.Finding, derivedChecks []string, derive func([]alert.Finding) []alert.Finding) {
	s.PurgeAndMergeFindingsDerivedWithCoverage(purgeChecks, findings, nil, derivedChecks, derive)
}

// PurgeAndMergeFindingsDerivedWithGaps preserves current findings for path
// aliases captured when the completed scan observed a coverage gap. Callers
// must supply both lexical and resolved aliases they accepted at scan time;
// preservation is evaluated under latestMu without resolving them again.
func (s *Store) PurgeAndMergeFindingsDerivedWithGaps(purgeChecks []string, findings []alert.Finding, preserveAliasesByCheck map[string]map[string]bool, derivedChecks []string, derive func([]alert.Finding) []alert.Finding) {
	s.PurgeAndMergeFindingsDerivedWithCoverage(purgeChecks, findings, &ScanCoverage{PreservePaths: preserveAliasesByCheck}, derivedChecks, derive)
}

// PurgeAndMergeFindingsDerivedWithCoverage applies file gaps and completed
// scanner scopes against current state in the same transaction as correlation.
// It returns the current rows a purged check or a completed scope removed:
// rows that were preserved, automatically demoted or reported again in either
// pass are not retired, and neither are rows the active-set cap dropped.
// The keys of every other current row are returned as kept: those
// conditions are still present.
func (s *Store) PurgeAndMergeFindingsDerivedWithCoverage(purgeChecks []string, findings []alert.Finding, coverage *ScanCoverage, derivedChecks []string, derive func([]alert.Finding) []alert.Finding) (retired []alert.Finding, kept []string) {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()

	current := s.latestFindings
	merged, retired := purgeAndMergeLatestWithCoverage(current, purgeChecks, findings, coverage, true)
	if derive != nil {
		derived := derive(append([]alert.Finding(nil), merged...))
		var derivedRetired []alert.Finding
		merged, derivedRetired = purgeAndMergeLatestWithCoverage(merged, derivedChecks, derived, coverage, false)
		rederived := findingsByKey(derived)
		n := 0
		for _, f := range retired {
			if _, ok := rederived[f.Key()]; !ok {
				retired[n] = f
				n++
			}
		}
		retired = append(retired[:n], derivedRetired...)
	}
	gone := findingsByKey(retired)
	kept = make([]string, 0, len(current))
	for _, f := range current {
		key := f.Key()
		if _, ok := gone[key]; !ok {
			kept = append(kept, key)
		}
	}
	s.latestFindings = merged
	s.latestScanTime = time.Now()
	s.persistLatestLocked()
	return retired, kept
}

// earliestObservation resolves the first-seen time a re-reported finding
// keeps. The stored row wins because it was there first; a row written before
// FirstSeen existed contributes its Timestamp instead, so upgrading does not
// reset the history of every long-lived finding. A finding nobody stored
// before starts from its own timestamp.
func earliestObservation(stored, reported alert.Finding) time.Time {
	candidates := []time.Time{stored.FirstSeen, stored.Timestamp, reported.FirstSeen, reported.Timestamp}
	var earliest time.Time
	for _, t := range candidates {
		if t.IsZero() {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	return earliest
}

// purgeAndMergeLatest drops findings owned by purgeChecks (and the timeout
// findings those runners produced), merges findings by key, and returns the
// ordered, capped result.
func purgeAndMergeLatest(current []alert.Finding, purgeChecks []string, findings []alert.Finding, preservePathsByCheck map[string]map[string]bool) []alert.Finding {
	merged, _ := purgeAndMergeLatestWithCoverage(current, purgeChecks, findings, &ScanCoverage{PreservePaths: preservePathsByCheck}, true)
	return merged
}

// purgeAndMergeLatestWithCoverage also returns the current rows it retired:
// those neither kept nor reported again, measured before the cap.
func purgeAndMergeLatestWithCoverage(current []alert.Finding, purgeChecks []string, findings []alert.Finding, coverage *ScanCoverage, retireScopes bool) ([]alert.Finding, []alert.Finding) {
	if coverage == nil {
		coverage = &ScanCoverage{}
	}
	preservePathsByCheck := coverage.PreservePaths
	remove := make(map[string]bool, len(purgeChecks))
	for _, c := range purgeChecks {
		remove[c] = true
	}
	existing := make(map[string]alert.Finding, len(current)+len(findings))
	// Owner replacement removes old rows from the output, but a key reported
	// again in this merge must inherit its pre-purge observation. This history
	// lasts only for this merge; resolved keys leave no tombstone behind.
	observations := make(map[string]time.Time, len(current)+len(findings))
	preserveAliases := normalizedPreservePathAliases(preservePathsByCheck)
	preservationActive := preservePathsByCheck != nil
	mismatchedCarryKeys := make(map[string]struct{})
	holdChecks := make(map[string]bool)
	if preservationActive {
		for _, f := range findings {
			if !f.ScanCarryForward {
				continue
			}
			if pathMatchesPreservedAliases(f.FilePath, preserveAliases[f.Check]) {
				continue
			}
			// Carry-forward and preservation metadata must describe the same
			// scope. If they ever disagree, retain the whole owner rather than
			// choosing between a purge and a stale resurrection.
			holdChecks[f.Check] = true
			mismatchedCarryKeys[f.Key()] = struct{}{}
		}
	}
	protectedKeys := make(map[string]struct{})
	scopeProtectedKeys := make(map[string]struct{})
	for _, f := range current {
		key := f.Key()
		observations[key] = earliestObservation(alert.Finding{}, f)
		// A finding this package demoted is waiting on the re-verifier, which
		// reads the file, not on a scan that merely did not raise it again.
		// Purging it here would discard the demotion state and let the same
		// file come back at full severity on the next detection, so the
		// demotion has to outlive a negative scan. A fresh finding normally
		// replaces it below; a protected snapshot stays authoritative against a
		// colliding finding from another path.
		preserved := holdChecks[f.Check] || pathMatchesPreservedAliases(f.FilePath, preserveAliases[f.Check])
		retire := shouldPurgeLatestFinding(f, remove) || (retireScopes && coverage.completed(f))
		if preserved || isAutomaticallyDemotedFinding(f) || !retire {
			existing[key] = f
			if coverage.unexamined(f) {
				scopeProtectedKeys[key] = struct{}{}
			}
			if preserved {
				protectedKeys[key] = struct{}{}
			}
		}
	}
	for _, f := range findings {
		// Marked carry-forward state came from the scanner's earlier snapshot.
		// The current set under latestMu is authoritative: overwriting it would
		// undo a concurrent update, and inserting it when absent would resurrect
		// a concurrent dismissal. A genuinely fresh detection has no marker.
		if preservationActive && f.ScanCarryForward {
			continue
		}
		key := f.Key()
		if _, staleSnapshot := mismatchedCarryKeys[key]; staleSnapshot {
			continue
		}
		if _, currentIsAuthoritative := protectedKeys[key]; currentIsAuthoritative &&
			!pathMatchesPreservedAliases(f.FilePath, preserveAliases[f.Check]) {
			continue
		}
		f.ScanCarryForward = false
		f.FirstSeen = earliestObservation(alert.Finding{FirstSeen: observations[key]}, f)
		observations[key] = f.FirstSeen
		existing[key] = f
		if pathMatchesPreservedAliases(f.FilePath, preserveAliases[f.Check]) {
			protectedKeys[key] = struct{}{}
		}
	}
	// Protect only previously admitted unexamined findings. New partial
	// detections compete for the remaining slots; protecting them too would
	// let a persistently incomplete scanner grow the active set without bound.
	// Refreshes of retained keys keep their protection and original first-seen.
	for key := range scopeProtectedKeys {
		protectedKeys[key] = struct{}{}
	}
	var retired []alert.Finding
	for _, f := range current {
		if _, ok := existing[f.Key()]; !ok {
			retired = append(retired, f)
		}
	}
	return orderAndCapLatestPreserving(existing, protectedKeys), retired
}

func normalizedPreservePathAliases(pathsByCheck map[string]map[string]bool) map[string]map[string]struct{} {
	if len(pathsByCheck) == 0 {
		return nil
	}
	aliasesByCheck := make(map[string]map[string]struct{}, len(pathsByCheck))
	for check, paths := range pathsByCheck {
		if len(paths) == 0 {
			continue
		}
		aliases := make(map[string]struct{}, len(paths)*2)
		for path := range paths {
			// The scanner already captured both lexical and symlink-resolved
			// identities at gap time. Re-resolving here would let a symlink
			// retarget between scan and merge change which file is protected.
			if alias := normalizedLatestFindingPath(path); alias != "" {
				aliases[alias] = struct{}{}
			}
		}
		aliasesByCheck[check] = aliases
	}
	return aliasesByCheck
}

func pathMatchesPreservedAliases(path string, preserved map[string]struct{}) bool {
	if path == "" || len(preserved) == 0 {
		return false
	}
	for _, alias := range latestFindingPathAliases(path) {
		if _, ok := preserved[alias]; ok {
			return true
		}
	}
	return false
}

func latestFindingPathAliases(path string) []string {
	if path == "" {
		return nil
	}
	lexical := filepath.Clean(path)
	if absolute, err := filepath.Abs(lexical); err == nil {
		lexical = filepath.Clean(absolute)
	}
	aliases := []string{lexical}
	if real, err := filepath.EvalSymlinks(lexical); err == nil {
		real = filepath.Clean(real)
		if real != lexical {
			aliases = append(aliases, real)
		}
	}
	return aliases
}

func normalizedLatestFindingPath(path string) string {
	if path == "" {
		return ""
	}
	lexical := filepath.Clean(path)
	if absolute, err := filepath.Abs(lexical); err == nil {
		lexical = filepath.Clean(absolute)
	}
	return lexical
}

// latestFindingsCap bounds the active set to keep memory and the persisted
// file bounded; the ordering below decides what the cap keeps.
const latestFindingsCap = 15000

// orderAndCapLatest flattens a keyed set into a deterministic order:
// severity first, then most recent, then key. Map iteration order used to
// decide both the file bytes and which findings a full set dropped.
func orderAndCapLatest(existing map[string]alert.Finding) []alert.Finding {
	return orderAndCapLatestPreserving(existing, nil)
}

func orderAndCapLatestPreserving(existing map[string]alert.Finding, protected map[string]struct{}) []alert.Finding {
	merged := make([]alert.Finding, 0, len(existing))
	for _, f := range existing {
		merged = append(merged, f)
	}
	sort.Slice(merged, func(i, j int) bool {
		if merged[i].Severity != merged[j].Severity {
			return merged[i].Severity > merged[j].Severity
		}
		if !merged[i].Timestamp.Equal(merged[j].Timestamp) {
			return merged[i].Timestamp.After(merged[j].Timestamp)
		}
		return merged[i].Key() < merged[j].Key()
	})
	if len(merged) <= latestFindingsCap {
		return merged
	}
	protectedCount := 0
	for _, f := range merged {
		if _, ok := protected[f.Key()]; ok {
			protectedCount++
		}
	}
	if protectedCount == 0 {
		return merged[:latestFindingsCap]
	}

	// A preservation transaction must not retire an unexamined finding merely
	// because newly merged, higher-severity findings reached the normal cap.
	// Keep every protected identity, then fill the remaining slots in the same
	// deterministic priority order. In the pathological case that protected
	// state alone exceeds the cap, the coverage invariant wins temporarily.
	unprotectedSlots := latestFindingsCap - protectedCount
	if unprotectedSlots < 0 {
		unprotectedSlots = 0
	}
	capped := make([]alert.Finding, 0, max(latestFindingsCap, protectedCount))
	for _, f := range merged {
		if _, ok := protected[f.Key()]; ok {
			capped = append(capped, f)
			continue
		}
		if unprotectedSlots > 0 {
			capped = append(capped, f)
			unprotectedSlots--
		}
	}
	return capped
}

// latestFindingsWriter writes the persisted file; a seam for tests.
var latestFindingsWriter = atomicio.AtomicWrite

// persistLatestLocked writes latest_findings.json when its content changed
// since the last write. Callers hold latestMu. Compact JSON: the file is
// read back by this process only.
func (s *Store) persistLatestLocked() {
	data, err := json.Marshal(s.latestFindings)
	if err != nil {
		return
	}
	digest := sha256.Sum256(data)
	if s.latestDigestSet && digest == s.latestDigest {
		return
	}
	path := filepath.Join(s.path, "latest_findings.json")
	// Older releases wrote through a fixed <path>.tmp; clear one left by a
	// crash so it cannot be mistaken for live state.
	if err := os.Remove(path + ".tmp"); err != nil && !os.IsNotExist(err) {
		return
	}
	if err := latestFindingsWriter(path, 0o600, data); err != nil {
		return
	}
	s.latestDigest = digest
	s.latestDigestSet = true
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
	s.persistLatestLocked()
}

// DemoteLatestFinding conditionally lowers a finding's severity in the latest
// scan results. The expected snapshot prevents a completed scan or realtime
// alert from being overwritten by an older re-verification result.
//
// Check, Message and Details never change. Finding.Key() hashes those fields,
// so an explanation written into the finding would orphan every dismissal,
// suppression and alert-dedup entry already keyed to it. DemotedFrom records
// only the severity needed to reverse the operation.
func (s *Store) DemoteLatestFinding(expected alert.Finding, severity alert.Severity) bool {
	if severity != alert.Warning || expected.Severity < alert.High || expected.Severity > alert.Critical {
		return false
	}
	s.latestMu.Lock()
	defer s.latestMu.Unlock()

	for i := range s.latestFindings {
		current := &s.latestFindings[i]
		if current.Key() != expected.Key() || current.Severity <= severity {
			continue
		}
		if !sameLatestFindingSnapshot(*current, expected) {
			return false
		}
		current.DemotedFrom = current.Severity
		current.Severity = severity
		s.latestFindings = orderAndCapLatest(findingsByKey(s.latestFindings))
		s.persistLatestLocked()
		return true
	}
	return false
}

// PrepareFindingResolution captures the listing and alert observation before a
// fix or re-check starts. Call the returned function only after recovery is
// proven. New evidence or a later operator decision invalidates the capture.
// Delivery receipts are deliberately excluded: finishing an email does not
// change the evidence, and deleting its entry invalidates any pending receipt.
func (s *Store) PrepareFindingResolution(expected alert.Finding) func() bool {
	s.latestMu.RLock()
	defer s.latestMu.RUnlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := expected.Key()
	if expected.Check == "" || strings.HasPrefix(key, "_") {
		return func() bool { return false }
	}
	listed := false
	for _, current := range s.latestFindings {
		if current.Key() != key {
			continue
		}
		if !sameLatestFindingSnapshot(current, expected) {
			return func() bool { return false }
		}
		listed = true
		break
	}
	entry := s.entries[key]
	// An unlisted producer may have alert state before it has a UI row. It
	// must not resolve someone else's evidence or an operator dismissal.
	if !listed && entry != nil && (entry.Hash != findingHash(expected) || entry.IsBaseline) {
		return func() bool { return false }
	}
	var observation uint64
	var baseline bool
	var dismissal string
	if entry != nil {
		observation, baseline, dismissal = entry.observation, entry.IsBaseline, entry.DismissalID
	}
	return func() bool {
		s.latestMu.Lock()
		defer s.latestMu.Unlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		currentEntry := s.entries[key]
		// BeginDelivery may create an entry while remediation runs. Unlike an
		// Update observation it has no evidence revision and may still be cleared.
		deliveryOnly := entry == nil && currentEntry != nil && currentEntry.observation == 0 && currentEntry.Hash == findingHash(expected)
		if (currentEntry != entry && !deliveryOnly) || (currentEntry != nil &&
			(currentEntry.observation != observation || currentEntry.IsBaseline != baseline || currentEntry.DismissalID != dismissal)) {
			return false
		}
		index := -1
		for i, current := range s.latestFindings {
			if current.Key() != key {
				continue
			}
			if !listed || !sameLatestFindingSnapshot(current, expected) {
				return false
			}
			index = i
			break
		}
		if listed && index == -1 {
			return false
		}
		if s.deleteRawLocked(key) {
			if err := s.save(); err != nil {
				fmt.Fprintf(os.Stderr, "state: error saving resolved finding: %v\n", err)
			}
		}
		if index != -1 {
			s.latestFindings = append(s.latestFindings[:index], s.latestFindings[index+1:]...)
			s.persistLatestLocked()
		}
		return true
	}
}

// RestoreLatestFindingSeverity reverses an automatic demotion after the exact
// verifier that owns the finding reports the content as live again.
func (s *Store) RestoreLatestFindingSeverity(expected alert.Finding) bool {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()

	for i := range s.latestFindings {
		current := &s.latestFindings[i]
		if current.Key() != expected.Key() || !isAutomaticallyDemotedFinding(*current) {
			continue
		}
		if !sameLatestFindingSnapshot(*current, expected) {
			return false
		}
		current.Severity = current.DemotedFrom
		current.DemotedFrom = alert.Warning
		s.latestFindings = orderAndCapLatest(findingsByKey(s.latestFindings))
		s.persistLatestLocked()
		return true
	}
	return false
}

func isAutomaticallyDemotedFinding(f alert.Finding) bool {
	return f.Severity == alert.Warning &&
		f.DemotedFrom >= alert.High && f.DemotedFrom <= alert.Critical
}

// sameLatestFindingSnapshot reports whether the stored finding is still the one
// verification looked at. Any field the verifier's decision rested on must
// match, or a newer detection would be silently overwritten by a stale verdict.
func sameLatestFindingSnapshot(current, expected alert.Finding) bool {
	if current.Key() != expected.Key() ||
		current.Check != expected.Check ||
		current.Message != expected.Message ||
		current.Details != expected.Details ||
		current.Severity != expected.Severity ||
		!current.Timestamp.Equal(expected.Timestamp) ||
		current.FilePath != expected.FilePath ||
		current.ContentSHA256 != expected.ContentSHA256 ||
		current.DetectLogic != expected.DetectLogic {
		return false
	}
	return current.DemotedFrom == expected.DemotedFrom
}

func findingsByKey(findings []alert.Finding) map[string]alert.Finding {
	keyed := make(map[string]alert.Finding, len(findings))
	for _, finding := range findings {
		keyed[finding.Key()] = finding
	}
	return keyed
}

// DismissFinding marks a finding as baseline (acknowledged/dismissed).
// It will no longer appear in active findings or trigger new alerts.
func (s *Store) DismissFinding(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, exists := s.entries[key]; exists {
		entry.IsBaseline = true
		entry.DismissalID = ""
		s.dirty = true
	}
}

// DismissUndo records what DismissFindingWithUndo changed, so UndoDismiss can
// return the finding to the state it had before the operator dismissed it.
type DismissUndo struct {
	Key string `json:"key"`
	// Identity and hash prevent an old undo from reversing a later decision
	// or changing alert state for newer evidence under the same key.
	DismissalID   string          `json:"dismissal_id"`
	Hash          string          `json:"hash"`
	ClearBaseline bool            `json:"clear_baseline,omitempty"`
	CreatedEntry  bool            `json:"created_entry,omitempty"`
	Removed       []alert.Finding `json:"removed,omitempty"`
	// PrevContent is nil when an earlier baseline's content was left alone.
	// Undo must preserve evidence that baseline adopts after the dismissal.
	PrevContent *string `json:"prev_content,omitempty"`
}

// DismissFindingWithUndo marks a finding as baseline and removes it from the
// latest list as one operation. Latest-only findings also need alert state:
// realtime findings can reach the UI before the next scan updates dedup state.
// The dismissal covers the content of the listed row.
func (s *Store) DismissFindingWithUndo(key string) DismissUndo {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	u, _ := s.dismissLocked(key, nil)
	return u
}

// DismissFindingAsShown dismisses key only while every listed row for it
// still carries shown, the content hash the operator judged (empty for a
// finding without one). A row whose content changed since it was shown is
// refused with nothing changed, so new content is reviewed before it is
// dismissed.
func (s *Store) DismissFindingAsShown(key, shown string) (DismissUndo, bool) {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dismissLocked(key, &shown)
}

// dismissLocked runs under latestMu and mu. A nil shown makes no claim.
func (s *Store) dismissLocked(key string, shown *string) (DismissUndo, bool) {
	u := DismissUndo{Key: key}
	var kept []alert.Finding
	for _, f := range s.latestFindings {
		if f.Key() == key {
			if shown != nil && f.ContentSHA256 != *shown {
				return DismissUndo{Key: key}, false
			}
			u.Removed = append(u.Removed, f)
			continue
		}
		kept = append(kept, f)
	}
	var content string
	switch {
	case shown != nil:
		content = *shown
	case len(u.Removed) > 0:
		content = u.Removed[0].ContentSHA256
	}
	entry := s.entries[key]
	if entry == nil && len(u.Removed) > 0 {
		now := time.Now()
		entry = &Entry{Hash: findingHash(u.Removed[0]), FirstSeen: now, LastSeen: now}
		s.entries[key] = entry
		u.CreatedEntry = true
	}
	if entry != nil {
		u.ClearBaseline = !entry.IsBaseline
		if u.ClearBaseline || (content != "" && content != entry.ContentSHA256) {
			previous := entry.ContentSHA256
			u.PrevContent = &previous
		}
		entry.IsBaseline = true
		if content != "" {
			entry.ContentSHA256 = content
		}
		entry.DismissalID = rand.Text()
		u.DismissalID, u.Hash = entry.DismissalID, entry.Hash
		s.dirty = true
	}
	s.latestFindings = kept
	s.persistLatestLocked()
	return u, true
}

// UndoDismiss reverses only the dismissal that still owns the entry. A copy
// reported by a scan in the meantime is newer evidence and remains listed.
func (s *Store) UndoDismiss(u DismissUndo) bool {
	s.latestMu.Lock()
	defer s.latestMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.entries[u.Key]
	if u.DismissalID == "" || entry == nil || entry.DismissalID != u.DismissalID || entry.Hash != u.Hash {
		return false
	}
	entry.DismissalID = ""
	if u.PrevContent != nil {
		entry.ContentSHA256 = *u.PrevContent
	}
	if u.CreatedEntry {
		delete(s.entries, u.Key)
	} else if u.ClearBaseline {
		entry.IsBaseline = false
	}
	s.dirty = true
	if len(u.Removed) > 0 {
		merged := findingsByKey(s.latestFindings)
		for _, f := range u.Removed {
			if _, present := merged[f.Key()]; !present {
				merged[f.Key()] = f
			}
		}
		s.latestFindings = orderAndCapLatest(merged)
		s.persistLatestLocked()
	}
	return true
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
// Callers that change the existing rules use UpdateSuppressions instead.
func (s *Store) SaveSuppressions(rules []SuppressionRule) error {
	return atomicio.AtomicWriteJSON(filepath.Join(s.path, "suppressions.json"), 0o600, rules)
}

// UpdateSuppressions applies fn to the stored rules and saves what it returns
// as one step. An error from fn leaves the stored rules unchanged.
func (s *Store) UpdateSuppressions(fn func([]SuppressionRule) ([]SuppressionRule, error)) error {
	s.suppressMu.Lock()
	defer s.suppressMu.Unlock()
	rules, err := fn(s.LoadSuppressions())
	if err != nil {
		return err
	}
	return s.SaveSuppressions(rules)
}

// IsSuppressed checks if a finding matches any loaded suppression rule.
// Load rules once with LoadSuppressions() and pass them in to avoid
// re-reading the file for every finding.
func (s *Store) IsSuppressed(f alert.Finding, rules []SuppressionRule) bool {
	for _, rule := range rules {
		if config.CanonicalCheckName(f.Check) != config.CanonicalCheckName(rule.Check) {
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
