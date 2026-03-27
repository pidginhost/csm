package attackdb

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const statsCacheTTL = 30 * time.Second

// AttackStats contains aggregate statistics for the API and dashboard.
type AttackStats struct {
	TotalIPs      int                `json:"total_ips"`
	TotalEvents   int                `json:"total_events"`
	Last24hEvents int                `json:"last_24h_events"`
	Last7dEvents  int                `json:"last_7d_events"`
	BlockedIPs    int                `json:"blocked_ips"`
	ByType        map[AttackType]int `json:"by_type"`
	TopAttackers  []*IPRecord        `json:"top_attackers"`
	HourlyBuckets [24]int            `json:"hourly_buckets"` // last 24h, index 0 = oldest hour
	DailyBuckets  [7]int             `json:"daily_buckets"`  // last 7 days, index 0 = oldest day
}

var (
	cachedStats     AttackStats
	cachedStatsTime time.Time
	cachedStatsMu   sync.Mutex
)

// Stats returns aggregate statistics, cached for 30 seconds to avoid
// re-scanning the full events.jsonl on every API call.
func (db *DB) Stats() AttackStats {
	cachedStatsMu.Lock()
	if time.Since(cachedStatsTime) < statsCacheTTL {
		s := cachedStats
		cachedStatsMu.Unlock()
		return s
	}
	cachedStatsMu.Unlock()

	stats := db.computeStats()

	cachedStatsMu.Lock()
	cachedStats = stats
	cachedStatsTime = time.Now()
	cachedStatsMu.Unlock()

	return stats
}

func (db *DB) computeStats() AttackStats {
	now := time.Now()
	cutoff24h := now.Add(-24 * time.Hour)
	cutoff7d := now.Add(-7 * 24 * time.Hour)

	db.mu.RLock()
	stats := AttackStats{
		TotalIPs: len(db.records),
		ByType:   make(map[AttackType]int),
	}

	for _, rec := range db.records {
		stats.TotalEvents += rec.EventCount
		if rec.AutoBlocked {
			stats.BlockedIPs++
		}
		for atype, count := range rec.AttackCounts {
			stats.ByType[atype] += count
		}
	}
	db.mu.RUnlock()

	// Compute time-based stats from events log
	events := db.readAllEvents()
	for _, ev := range events {
		if ev.Timestamp.After(cutoff24h) {
			stats.Last24hEvents++
			hoursAgo := int(now.Sub(ev.Timestamp).Hours())
			if hoursAgo >= 0 && hoursAgo < 24 {
				stats.HourlyBuckets[23-hoursAgo]++
			}
		}
		if ev.Timestamp.After(cutoff7d) {
			stats.Last7dEvents++
			daysAgo := int(now.Sub(ev.Timestamp).Hours() / 24)
			if daysAgo >= 0 && daysAgo < 7 {
				stats.DailyBuckets[6-daysAgo]++
			}
		}
	}

	stats.TopAttackers = db.TopAttackers(10)

	return stats
}

// readAllEvents reads all events from the JSONL file (for stats computation).
func (db *DB) readAllEvents() []Event {
	path := filepath.Join(db.dbPath, eventsFile)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var events []Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var ev Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		events = append(events, ev)
	}
	return events
}
