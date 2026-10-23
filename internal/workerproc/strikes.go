package workerproc

import (
	"sync"
	"time"
)

const (
	// StrikeLimit is how many worker failures within StrikeTTL block an
	// input. An input that kills a worker every time would otherwise cost a
	// worker on every scan, and keep its check incomplete forever.
	StrikeLimit = 2
	// StrikeTTL is how long a failure counts against an input.
	StrikeTTL = 24 * time.Hour
	// maxStrikeKeys bounds memory; when full, the input whose last failure
	// is oldest is forgotten.
	maxStrikeKeys = 1024
)

// Strikes remembers inputs, by key, that made a worker fail.
type Strikes struct {
	mu      sync.Mutex
	entries map[string]strike
	now     func() time.Time
}

type strike struct {
	count int
	last  time.Time
}

// NewStrikes returns an empty record.
func NewStrikes() *Strikes {
	return &Strikes{entries: make(map[string]strike), now: time.Now}
}

// Record counts one worker failure on key.
func (s *Strikes) Record(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e, ok := s.entries[key]
	if ok && now.Sub(e.last) > StrikeTTL {
		e = strike{}
	}
	if !ok && len(s.entries) >= maxStrikeKeys {
		// A worker failure is rare enough to scan this bounded table.
		oldest := ""
		for k, v := range s.entries {
			if oldest == "" || v.last.Before(s.entries[oldest].last) {
				oldest = k
			}
		}
		delete(s.entries, oldest)
	}
	e.count++
	e.last = now
	s.entries[key] = e
}

// Blocked reports StrikeLimit or more failures on key, the last within
// StrikeTTL.
func (s *Strikes) Blocked(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	return ok && e.count >= StrikeLimit && s.now().Sub(e.last) <= StrikeTTL
}

// Len is how many inputs have unexpired failures. Dropping expired entries
// lets callers avoid hashing every input once the failure window has passed.
func (s *Strikes) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, entry := range s.entries {
		if now.Sub(entry.last) > StrikeTTL {
			delete(s.entries, key)
		}
	}
	return len(s.entries)
}
