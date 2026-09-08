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
// The attack database accumulates; ComputeScore has no recency term and
// pruneExpired only runs at 90 days. So when a detection bug attributes
// events to the wrong address, fixing the detection stops new events but
// leaves the accrued ones behind, and local_threat_score keeps reporting
// the stale score for the rest of the retention window.
//
// The Web UI could already clear a record, but only inside whitelist-ip,
// which also unblocks the address, adds it to the firewall allow list and
// whitelists it in the threat DB. That is the wrong trade for clearing
// stale data: it permanently exempts the address from future detection.
// This command touches the scoring state and nothing else, so a cleared
// address is scored again from scratch the next time it does something.
func (c *ControlListener) handleThreatForget(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallIPArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if net.ParseIP(args.IP) == nil {
		return nil, fmt.Errorf("invalid ip: %q", args.IP)
	}

	adb := attackdb.Global()
	if adb == nil {
		return nil, fmt.Errorf("attack database unavailable")
	}

	// Read the record before removing it so the operator is told what was
	// actually cleared rather than that the command ran.
	res := control.ThreatForgetResult{IP: args.IP}
	if rec := adb.LookupIP(args.IP); rec != nil {
		res.Found = true
		res.Score = attackdb.ComputeScore(rec)
		res.Events = rec.EventCount
	}

	if !res.Found {
		res.Message = fmt.Sprintf("No local threat record for %s; nothing cleared", args.IP)
		return res, nil
	}

	adb.RemoveIP(args.IP)
	// Persist immediately. The background saver runs every 30s and a
	// restart inside that window would reload the record we just cleared,
	// which is exactly the symptom this command exists to end.
	if err := adb.Flush(); err != nil {
		return nil, fmt.Errorf("removed %s from memory but could not persist: %w", args.IP, err)
	}

	res.Message = fmt.Sprintf(
		"Cleared local threat record for %s (was score %d/100, %d attack events); block, allow and whitelist entries are unchanged",
		args.IP, res.Score, res.Events)
	return res, nil
}
