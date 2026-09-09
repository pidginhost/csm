package health

import (
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

// Snapshot is the unified machine-readable health view assembled from the
// running daemon (or, on a cold lookup, from on-disk state). It is the
// single source of truth for /api/v1/status, csm status --json, csm doctor,
// and the sd_notify readiness gate.
type Snapshot struct {
	Queues   map[string]queuehealth.Status `json:"queues,omitempty"`
	Version  string                        `json:"version"`
	Hostname string                        `json:"hostname"`
	// Mode is the operator's posture: "enforce" or "observe". An observe
	// host runs detection and alerting but changes no host state.
	Mode                 string          `json:"mode,omitempty"`
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
	// Cleared whenever auto-response is live; dry-run mode keeps a recent
	// rolling window for operator review.
	DryRunBlocks int `json:"dry_run_blocks,omitempty"`

	// Automation is the operator-facing safety surface for automatic action
	// rollout. It groups dry-run state, challenge routing, pending firewall
	// rollback, and the last recorded automation action in one stable payload.
	Automation AutomationStatus `json:"automation,omitempty"`

	// CorrelationAttribution reports which checks feed cross-account
	// correlation findings without a hosting owner. Nil until the daemon has
	// merged an active set, and on daemons that predate the block.
	CorrelationAttribution *CorrelationAttribution `json:"correlation_attribution,omitempty"`

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
	AutoResponseEnabled  bool `json:"auto_response_enabled"`
	AutoResponseBlockIPs bool `json:"auto_response_block_ips"`
	AutoResponseDryRun   bool `json:"auto_response_dry_run"`
	// Termination needs a kernel process handle. A kernel that cannot pin one
	// leaves configured automatic killing inoperative, so the capability and
	// its cause travel with the status instead of staying in the log.
	ProcessKillEnabled       bool   `json:"process_kill_enabled"`
	ProcessSignalSupported   bool   `json:"process_signal_supported"`
	ProcessSignalError       string `json:"process_signal_error,omitempty"`
	DryRunBlocks             int    `json:"dry_run_blocks"`
	ChallengeEnabled         bool   `json:"challenge_enabled"`
	ChallengePortGateEnabled bool   `json:"challenge_port_gate_enabled"`
	ChallengePortGateActive  bool   `json:"challenge_port_gate_active"`
	ChallengePending         int    `json:"challenge_pending"`
	ChallengeEscalated       int    `json:"challenge_escalated"`
	// FirewallEnabled reflects firewall.enabled in config. FirewallManaged is
	// true only when the daemon has a live nftables engine wired. The
	// combination FirewallEnabled && !FirewallManaged means the firewall is
	// configured on but the daemon is NOT managing it (e.g. the engine failed
	// to apply at startup) -- a condition monitoring should alert on.
	FirewallEnabled               bool              `json:"firewall_enabled"`
	FirewallManaged               bool              `json:"firewall_managed"`
	FirewallStartupError          string            `json:"firewall_startup_error,omitempty"`
	FirewallBlockedIPs            int               `json:"firewall_blocked_ips"`
	FirewallBlockedSubnets        int               `json:"firewall_blocked_subnets"`
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

// CorrelationAttribution is the operator-facing view of cross-account
// correlation attribution. Current is the per-check count of qualifying
// findings in the latest-state active set that carry no hosting owner, as
// of its most recent merge; it clears when a later merge attributes them.
// Cumulative sums every unattributed row reported since the daemon started,
// across active-set merges and per-batch derivations, so a producer that
// recovered stays visible as having failed. Kept as its own type so
// internal/health does not import internal/checks.
type CorrelationAttribution struct {
	Current          map[string]int `json:"current"`
	Cumulative       map[string]int `json:"cumulative"`
	ActiveSetUpdates int            `json:"active_set_updates"`
	Since            time.Time      `json:"since"`
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
//   - "degraded" if a watcher is detached, the store is unhealthy, an enabled
//     firewall is unmanaged, enabled termination has no safe kernel path,
//     or a protection queue is degraded
//   - "ok" otherwise
func (s Snapshot) OverallStatus() string {
	if s.StartedAt.IsZero() && len(s.Watchers) == 0 {
		return "down"
	}
	if !s.StoreHealthy || !s.AllWatchersAttached() || s.Automation.FirewallEnabled && !s.Automation.FirewallManaged ||
		s.Automation.ProcessKillEnabled && !s.Automation.ProcessSignalSupported {
		return "degraded"
	}
	for _, q := range s.Queues {
		if q.Status == "degraded" {
			return "degraded"
		}
	}
	return "ok"
}
