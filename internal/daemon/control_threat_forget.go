package daemon

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/control"
)

// handleThreatForget drops one address's record from the attack database.
//
// Most score contributions last until the record expires after 90 days.
// Fixing a detection that attributed events to the wrong address stops new
// events but leaves those contributions behind.
//
// The Web UI's clear and whitelist actions also change enforcement.
// This command leaves enforcement and event history intact, so a cleared
// address is scored again from scratch on its next finding.
func (c *ControlListener) handleThreatForget(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallIPArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	ip := net.ParseIP(args.IP)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip: %q", args.IP)
	}
	args.IP = ip.String()

	adb := attackdb.Global()
	if adb == nil {
		return nil, fmt.Errorf("attack database unavailable")
	}

	// Read and remove under one lock so concurrent requests cannot claim
	// the same record, or report counts from before a concurrent finding.
	res := control.ThreatForgetResult{IP: args.IP}
	for _, rec := range adb.ForgetIP(ip) {
		res.Found = true
		res.Score = max(res.Score, attackdb.ComputeScore(rec))
		res.Events += rec.EventCount
	}

	if !res.Found {
		res.Message = fmt.Sprintf("No local threat record for %s; nothing cleared", args.IP)
		return res, nil
	}

	// Persist immediately rather than waiting for the 30s background saver:
	// Flush does not report persistence errors, so this remains best effort.
	// A lookup afterwards cannot verify persistence, and new findings may
	// legitimately have created a fresh record by then.
	_ = adb.Flush()

	res.Message = fmt.Sprintf(
		"Cleared local threat record for %s (was score %d/100, %d attack events); block, allow and whitelist entries are unchanged",
		args.IP, res.Score, res.Events)
	return res, nil
}
