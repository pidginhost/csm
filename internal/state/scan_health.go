package state

import (
	"fmt"
	"os"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// RearmAbsentDedupFindings forgets dismissals of resolved conditions, only for
// the finding names whose owner supplied a replacement scan result. Update
// cannot do this: its input may be an unrelated tier or realtime batch. An
// alerted, undismissed entry is kept: deep scans do not cover every file each
// cycle, so a condition that is absent for one run and back the next keeps its
// daily reminder instead of alerting on every return.
func (s *Store) RearmAbsentDedupFindings(checks []string, findings []alert.Finding) {
	if len(checks) == 0 {
		return
	}
	owners := make(map[string]bool, len(checks))
	for _, check := range checks {
		owners[check] = true
	}
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		seen[f.Key()] = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for key := range s.entries {
		identity, pinned := strings.CutPrefix(key, "dedup:")
		check, _, _ := strings.Cut(identity, ":")
		if pinned && owners[check] && !seen[key] && s.entries[key].IsBaseline {
			delete(s.entries, key)
			changed = true
		}
	}
	if changed {
		s.dirty = true
		if err := s.save(); err != nil {
			fmt.Fprintf(os.Stderr, "state: error saving resolved scan conditions: %v\n", err)
		}
	}
}

// RearmFindings resets specific conditions after their producer proves recovery.
// Other producers sharing a finding name keep their own alert history.
func (s *Store) RearmFindings(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, key := range keys {
		if s.deleteRawLocked(key) {
			changed = true
		}
	}
	if changed {
		if err := s.save(); err != nil {
			fmt.Fprintf(os.Stderr, "state: error saving recovered scan conditions: %v\n", err)
		}
	}
}

// RearmDismissedFindings re-arms specific conditions only where the operator
// dismissed them. An alerted, undismissed condition keeps its daily reminder.
func (s *Store) RearmDismissedFindings(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, key := range keys {
		if entry, ok := s.entries[key]; ok && entry.IsBaseline {
			delete(s.entries, key)
			changed = true
		}
	}
	if changed {
		s.dirty = true
		if err := s.save(); err != nil {
			fmt.Fprintf(os.Stderr, "state: error saving resolved scan conditions: %v\n", err)
		}
	}
}
