package daemon

import (
	"sync"
	"time"
)

// indexEntry maps a message ID to the per-message attribution recorded at
// acceptance. Used by Path 3 (Stage 2) to map delivery-failure log lines
// back to the originating script. Public field names because gob-encoded
// for bbolt persistence in Task C3.
type indexEntry struct {
	ScriptKey   string
	HeaderScore int
	SourceIP    string
	CPUser      string
	At          time.Time
}

// msgIDIndex stores indexEntry per msgID, served from memory.
// Bounded by maxEntries; overflow drops the oldest entry by acceptance time.
// Persistence to bbolt is handled by msgIndexPersister (Task C3).
type msgIDIndex struct {
	mu         sync.Mutex
	entries    map[string]indexEntry
	maxEntries int
	persister  *msgIndexPersister // nil in unit tests; real in production
}

func newMsgIDIndex(persister *msgIndexPersister, maxEntries int) *msgIDIndex {
	if maxEntries <= 0 {
		maxEntries = 200_000
	}
	return &msgIDIndex{
		entries:    make(map[string]indexEntry, 4096),
		maxEntries: maxEntries,
		persister:  persister,
	}
}

// Put records an entry. If the in-memory map exceeds maxEntries, the
// oldest entry by At is evicted from memory. The persister (if non-nil)
// receives the put asynchronously; persistence failure does not affect
// in-memory correctness.
func (i *msgIDIndex) Put(msgID string, e indexEntry) {
	i.mu.Lock()
	if _, ok := i.entries[msgID]; !ok && len(i.entries) >= i.maxEntries {
		i.evictOldestLocked()
	}
	i.entries[msgID] = e
	i.mu.Unlock()
	if i.persister != nil {
		i.persister.Enqueue(msgID, e)
	}
}

// Get returns the entry and whether it was present.
func (i *msgIDIndex) Get(msgID string) (indexEntry, bool) {
	i.mu.Lock()
	e, ok := i.entries[msgID]
	i.mu.Unlock()
	return e, ok
}

// Has reports whether msgID is present in memory.
func (i *msgIDIndex) Has(msgID string) bool {
	i.mu.Lock()
	_, ok := i.entries[msgID]
	i.mu.Unlock()
	return ok
}

// Len returns the number of entries currently in memory.
func (i *msgIDIndex) Len() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.entries)
}

// SweepMemory drops entries whose At is at or before cutoff.
// Called by Flow E's 1-min ticker with cutoff = now - 4h.
func (i *msgIDIndex) SweepMemory(cutoff time.Time) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	n := 0
	for id, e := range i.entries {
		if !e.At.After(cutoff) {
			delete(i.entries, id)
			n++
		}
	}
	return n
}

func (i *msgIDIndex) evictOldestLocked() {
	var oldestID string
	var oldestAt time.Time
	first := true
	for id, e := range i.entries {
		if first || e.At.Before(oldestAt) {
			oldestID = id
			oldestAt = e.At
			first = false
		}
	}
	if oldestID != "" {
		delete(i.entries, oldestID)
	}
}

// msgIndexPersister is implemented in Task C3 (async batched bbolt writer).
// Forward declaration here so msgIDIndex compiles; full type lives in
// php_relay_msgindex_bbolt.go.
type msgIndexPersister struct{}

// Stub Enqueue keeps msgIDIndex tests compilable; replaced by the real
// implementation in Task C3.
func (p *msgIndexPersister) Enqueue(msgID string, e indexEntry) {}
