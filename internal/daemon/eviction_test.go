package daemon

import (
	"testing"
	"time"
)

func TestEvictAccessLogStateRemovesOld(t *testing.T) {
	// Seed a tracker with old data.
	tracker := &accessLogTracker{
		lastSeen:       time.Now().Add(-2 * time.Hour),
		wpLoginAlerted: true,
	}
	accessLogTrackers.Store("203.0.113.5", tracker)
	defer accessLogTrackers.Delete("203.0.113.5")

	evictAccessLogState(time.Now())

	// Old tracker with no timestamps should be deleted.
	if _, loaded := accessLogTrackers.Load("203.0.113.5"); loaded {
		t.Error("old tracker should be evicted")
	}
}

func TestEvictAccessLogStateKeepsRecent(t *testing.T) {
	tracker := &accessLogTracker{
		lastSeen:     time.Now(),
		wpLoginTimes: []time.Time{time.Now()},
		xmlrpcTimes:  []time.Time{time.Now()},
	}
	accessLogTrackers.Store("198.51.100.1", tracker)
	defer accessLogTrackers.Delete("198.51.100.1")

	evictAccessLogState(time.Now())

	if _, loaded := accessLogTrackers.Load("198.51.100.1"); !loaded {
		t.Error("recent tracker should be kept")
	}
}

func TestEvictModSecStateRemovesOld(t *testing.T) {
	// Seed a dedup entry with an old timestamp.
	old := time.Now().Add(-2 * time.Hour)
	modsecDedup.Store("203.0.113.5:920420", old)
	defer modsecDedup.Delete("203.0.113.5:920420")

	evictModSecState(time.Now())

	if _, loaded := modsecDedup.Load("203.0.113.5:920420"); loaded {
		t.Error("old dedup entry should be evicted")
	}
}
