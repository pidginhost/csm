package health

import "time"

// Snapshot is the unified machine-readable health view assembled from the
// running daemon (or, on a cold lookup, from on-disk state). It is the
// single source of truth for /api/v1/status, csm status --json, csm doctor,
// and the sd_notify readiness gate.
type Snapshot struct {
	Version              string          `json:"version"`
	Hostname             string          `json:"hostname"`
	StartedAt            time.Time       `json:"started_at"`
	UptimeSec            int64           `json:"uptime_sec"`
	LatestScan           time.Time       `json:"latest_scan,omitempty"`
	BaselineAt           time.Time       `json:"baseline_at,omitempty"`
	BlocklistSize        int             `json:"blocklist_size"`
	IncidentsOpen        int             `json:"incidents_open"`
	BPFEnforcementActive bool            `json:"bpf_enforcement_active"`
	HistoryCount         int             `json:"history_count"`
	Severities           map[string]int  `json:"severities"` // "critical","high","warning"
	Watchers             map[string]bool `json:"watchers"`   // name -> attached
	StoreHealthy         bool            `json:"store_healthy"`
	StoreSizeMB          float64         `json:"store_size_mb"`
	ConfigHash           string          `json:"config_hash,omitempty"`
	BinaryHash           string          `json:"binary_hash,omitempty"`
	Capabilities         []string        `json:"capabilities,omitempty"`
	// DryRunBlocks is the count of firewall blocks that were intercepted by
	// auto_response.dry_run and logged rather than applied to nftables.
	// Non-zero only when dry_run has been active since the last daemon start.
	DryRunBlocks int `json:"dry_run_blocks,omitempty"`

	// Automation is the operator-facing safety surface for automatic action
	// rollout. It groups dry-run state, challenge routing, pending firewall
	// rollback, and the last recorded automation action in one stable payload.
	Automation AutomationStatus `json:"automation,omitempty"`

	// Update reports whether a newer CSM release is available upstream.
	// Populated by internal/updatecheck. Zero value means the checker has
	// not yet completed a poll (very early startup) or is disabled in
	// config.
	Update UpdateInfo `json:"update,omitempty"`
}

// AutomationStatus summarizes the live automation safety state. It is
// intentionally compact so status clients can decide whether the host is
// observe-only, actively mutating the firewall, or waiting for operator
// confirmation after a tentative firewall apply.
type AutomationStatus struct {
	AutoResponseEnabled           bool              `json:"auto_response_enabled"`
	AutoResponseBlockIPs          bool              `json:"auto_response_block_ips"`
	AutoResponseDryRun            bool              `json:"auto_response_dry_run"`
	DryRunBlocks                  int               `json:"dry_run_blocks"`
	ChallengeEnabled              bool              `json:"challenge_enabled"`
	ChallengePortGateEnabled      bool              `json:"challenge_port_gate_enabled"`
	ChallengePortGateActive       bool              `json:"challenge_port_gate_active"`
	ChallengePending              int               `json:"challenge_pending"`
	FirewallRollbackPending       bool              `json:"firewall_rollback_pending"`
	FirewallRollbackSecondsRemain int64             `json:"firewall_rollback_seconds_remaining,omitempty"`
	LastAction                    *AutomationAction `json:"last_action,omitempty"`
}

// AutomationAction is the newest action-like finding CSM recorded.
type AutomationAction struct {
	Check     string    `json:"check"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// UpdateInfo mirrors updatecheck.Info for the health snapshot. Kept
// as a separate type so internal/health does not import
// internal/updatecheck and create a cycle.
type UpdateInfo struct {
	LatestVersion string    `json:"latest_version,omitempty"`
	Available     bool      `json:"available,omitempty"`
	Source        string    `json:"source,omitempty"`
	CheckedAt     time.Time `json:"checked_at,omitempty"`
	Err           string    `json:"err,omitempty"`
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
