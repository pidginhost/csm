// Package control defines the wire protocol between the CSM daemon and
// its local command-line client. The daemon listens on a Unix socket and
// accepts one line-framed JSON request per connection, replying with one
// line-framed JSON response. All types defined here are stable enough to
// be imported by both sides.
package control

import (
	"encoding/json"

	"github.com/pidginhost/csm/internal/alert"
)

// DefaultSocketPath is the Unix socket the daemon binds and the client
// dials. It sits next to pam.sock under /var/run/csm so both follow the
// same directory permissions established by the daemon at startup.
const DefaultSocketPath = "/var/run/csm/control.sock"

// Command names. Use constants so typos fail at compile time.
const (
	CmdTierRun     = "tier.run"
	CmdStatus      = "status"
	CmdHistoryRead = "history.read"
	CmdRulesReload = "rules.reload"
	CmdGeoIPReload = "geoip.reload"

	// Phase 2 additions.
	CmdBaseline           = "baseline"
	CmdFirewallStatus     = "firewall.status"
	CmdFirewallPorts      = "firewall.ports"
	CmdFirewallGrep       = "firewall.grep"
	CmdFirewallAudit      = "firewall.audit"
	CmdFirewallBlock      = "firewall.block"
	CmdFirewallUnblock    = "firewall.unblock"
	CmdFirewallAllow      = "firewall.allow"
	CmdFirewallAllowPort  = "firewall.allow_port"
	CmdFirewallRemovePort = "firewall.remove_port"
	CmdFirewallTempBan    = "firewall.tempban"
	CmdFirewallTempAllow  = "firewall.tempallow"
	CmdFirewallDenySubnet = "firewall.deny_subnet"
	CmdFirewallRemSubnet  = "firewall.remove_subnet"
	CmdFirewallDenyFile   = "firewall.deny_file"
	CmdFirewallAllowFile  = "firewall.allow_file"
	CmdFirewallFlush      = "firewall.flush"
	CmdFirewallRestart    = "firewall.restart"
	CmdFirewallApplyConf  = "firewall.apply_confirmed"
	CmdFirewallConfirm    = "firewall.confirm"
)

// Request is the single JSON object the client sends per connection.
// Args is a raw message so each command defines its own typed payload
// without forcing the transport layer to know about every command.
type Request struct {
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Response is the single JSON object the daemon returns per connection.
// Ok=false means the request did not run to completion; inspect Error.
// Ok=true means the handler ran and Result holds the typed payload.
type Response struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// TierRunArgs carries parameters for CmdTierRun.
// Tier is one of "critical", "deep", or "all". Alerts=true feeds the
// daemon's normal alert pipeline; false means "scan and report counts
// only" (used by the CLI's dry-run `check-*` commands when they migrate).
type TierRunArgs struct {
	Tier   string `json:"tier"`
	Alerts bool   `json:"alerts"`
}

// TierRunResult summarises what the tier run produced. Findings is only
// populated when TierRunArgs.Alerts was false (the dry-run `csm check*`
// path) so live tier runs do not pay the marshalling cost for the
// no-op case.
type TierRunResult struct {
	Findings    int             `json:"findings"`
	NewFindings int             `json:"new_findings"`
	ElapsedMs   int64           `json:"elapsed_ms"`
	FindingList []alert.Finding `json:"finding_list,omitempty"`
}

// StatusResult mirrors what `csm status` historically printed.
type StatusResult struct {
	Version        string `json:"version"`
	UptimeSec      int64  `json:"uptime_sec"`
	LatestScanTime string `json:"latest_scan_time,omitempty"`
	LatestFindings int    `json:"latest_findings"`
	HistoryCount   int    `json:"history_count"`
	DroppedAlerts  int64  `json:"dropped_alerts"`
}

// HistoryReadArgs carries parameters for CmdHistoryRead.
type HistoryReadArgs struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// HistoryReadResult holds a page of historical findings, newest-first.
type HistoryReadResult struct {
	Findings []alert.Finding `json:"findings"`
	Total    int             `json:"total"`
}

// BaselineArgs carries parameters for CmdBaseline.
// Confirm mirrors the CLI's --confirm flag: required when existing
// history would be wiped.
type BaselineArgs struct {
	Confirm bool `json:"confirm"`
}

// BaselineResult reports what a fresh baseline wrote.
type BaselineResult struct {
	Findings       int    `json:"findings"`
	HistoryCleared int    `json:"history_cleared"`
	BinaryHash     string `json:"binary_hash"`
	ConfigHash     string `json:"config_hash"`
	// NeedsConfirm=true means the daemon refused because Confirm was
	// false and HistoryCleared would have been non-zero. The other
	// fields are populated so the CLI can print the same warning as
	// today without a second round trip.
	NeedsConfirm bool `json:"needs_confirm,omitempty"`
}

// FirewallIPArgs is shared by block / unblock / allow / remove-style
// commands that take a single IP and an optional reason.
type FirewallIPArgs struct {
	IP      string `json:"ip"`
	Reason  string `json:"reason,omitempty"`
	Timeout string `json:"timeout,omitempty"` // duration string for tempban/tempallow; empty = permanent
}

// FirewallPortArgs covers allow-port / remove-port.
type FirewallPortArgs struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Proto  string `json:"proto,omitempty"` // "tcp" or "udp"; empty = tcp
	Reason string `json:"reason,omitempty"`
}

// FirewallSubnetArgs covers deny-subnet / remove-subnet.
type FirewallSubnetArgs struct {
	CIDR   string `json:"cidr"`
	Reason string `json:"reason,omitempty"`
}

// FirewallFileArgs carries a batch of IPs for deny-file / allow-file.
// The client reads the file locally and sends the contents over the
// socket so the daemon does not need to open arbitrary paths.
type FirewallFileArgs struct {
	IPs    []string `json:"ips"`
	Reason string   `json:"reason,omitempty"`
}

// FirewallGrepArgs matches the CLI's positional pattern.
type FirewallGrepArgs struct {
	Pattern string `json:"pattern"`
}

// FirewallAuditArgs matches the CLI's optional limit.
type FirewallAuditArgs struct {
	Limit int `json:"limit"`
}

// FirewallApplyConfirmedArgs mirrors the CLI's minutes argument.
type FirewallApplyConfirmedArgs struct {
	Minutes int `json:"minutes"`
}

// FirewallAckResult is the minimal ack returned by mutating firewall
// commands that do not need to report state back (block, allow, etc).
// Message is a short human-readable string the CLI can print verbatim.
type FirewallAckResult struct {
	Message string `json:"message"`
}

// FirewallStatusResult mirrors what `csm firewall status` prints.
// Fields match the CLI output one-to-one so the client can format
// identically without calling firewall.LoadState itself.
type FirewallStatusResult struct {
	Enabled         bool                   `json:"enabled"`
	TCPIn           []string               `json:"tcp_in"`
	TCPOut          []string               `json:"tcp_out"`
	UDPIn           []string               `json:"udp_in"`
	UDPOut          []string               `json:"udp_out"`
	Restricted      []string               `json:"restricted"`
	PassiveFTPStart int                    `json:"passive_ftp_start"`
	PassiveFTPEnd   int                    `json:"passive_ftp_end"`
	InfraIPCount    int                    `json:"infra_ip_count"`
	BlockedCount    int                    `json:"blocked_count"`
	BlockedNetCount int                    `json:"blocked_net_count"`
	AllowedCount    int                    `json:"allowed_count"`
	SYNFlood        bool                   `json:"syn_flood"`
	ConnRateLimit   int                    `json:"conn_rate_limit"`
	LogDropped      bool                   `json:"log_dropped"`
	LogRate         int                    `json:"log_rate"`
	RecentBlocked   []FirewallBlockedEntry `json:"recent_blocked,omitempty"`
}

// FirewallBlockedEntry is one entry in FirewallStatusResult.RecentBlocked.
type FirewallBlockedEntry struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	BlockedAt string `json:"blocked_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// FirewallListResult is returned by ports / grep / audit: a freeform
// line-based payload the CLI prints verbatim.
type FirewallListResult struct {
	Lines []string `json:"lines"`
}
