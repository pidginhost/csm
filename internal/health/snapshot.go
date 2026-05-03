package health

import "time"

// Snapshot is the unified machine-readable health view assembled from the
// running daemon (or, on a cold lookup, from on-disk state). It is the
// single source of truth for /api/v1/status, csm status --json, csm doctor,
// and the sd_notify readiness gate.
type Snapshot struct {
	Version       string         `json:"version"`
	Hostname      string         `json:"hostname"`
	StartedAt     time.Time      `json:"started_at"`
	UptimeSec     int64          `json:"uptime_sec"`
	LatestScan    time.Time      `json:"latest_scan,omitempty"`
	BaselineAt    time.Time      `json:"baseline_at,omitempty"`
	BlocklistSize int            `json:"blocklist_size"`
	HistoryCount  int            `json:"history_count"`
	Severities    map[string]int `json:"severities"`         // "critical","high","medium","low","info"
	Watchers      map[string]bool `json:"watchers"`           // name -> attached
	StoreHealthy  bool           `json:"store_healthy"`
	StoreSizeMB   float64        `json:"store_size_mb"`
	ConfigHash    string         `json:"config_hash,omitempty"`
	BinaryHash    string         `json:"binary_hash,omitempty"`
	Capabilities  []string       `json:"capabilities,omitempty"`
}

// TotalFindings returns the sum across all severity buckets.
func (s Snapshot) TotalFindings() int {
	total := 0
	for _, v := range s.Severities {
		total += v
	}
	return total
}

// AllWatchersAttached reports whether every registered watcher is attached.
// An empty Watchers map returns false (we never claim ready before probing).
func (s Snapshot) AllWatchersAttached() bool {
	if len(s.Watchers) == 0 {
		return false
	}
	for _, attached := range s.Watchers {
		if !attached {
			return false
		}
	}
	return true
}

// OverallStatus collapses the snapshot into one of: "ok", "degraded", "down".
//   - "down" if the snapshot was zero-valued (never assembled)
//   - "degraded" if any watcher is detached or the store is unhealthy
//   - "ok" otherwise
func (s Snapshot) OverallStatus() string {
	if s.StartedAt.IsZero() && len(s.Watchers) == 0 {
		return "down"
	}
	if !s.StoreHealthy || !s.AllWatchersAttached() {
		return "degraded"
	}
	return "ok"
}
