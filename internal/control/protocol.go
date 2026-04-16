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

// TierRunResult summarises what the tier run produced.
type TierRunResult struct {
	Findings    int   `json:"findings"`
	NewFindings int   `json:"new_findings"`
	ElapsedMs   int64 `json:"elapsed_ms"`
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
