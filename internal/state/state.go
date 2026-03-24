package state

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
)

type Store struct {
	path    string
	entries map[string]*Entry
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
	return s.save()
}

func (s *Store) save() error {
	data, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.path, "state.json"), data, 0600)
}

func findingKey(f alert.Finding) string {
	return fmt.Sprintf("%s:%s", f.Check, f.Message)
}

func findingHash(f alert.Finding) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", f.Check, f.Message, f.Details)))
	return fmt.Sprintf("%x", h[:8])
}

func (s *Store) FilterNew(findings []alert.Finding) []alert.Finding {
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
	entry, ok := s.entries[key]
	if !ok {
		return "", false
	}
	return entry.Hash, true
}

func (s *Store) SetRaw(key, value string) {
	entry, exists := s.entries[key]
	if !exists {
		s.entries[key] = &Entry{
			Hash:      value,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
	} else {
		entry.Hash = value
		entry.LastSeen = time.Now()
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
