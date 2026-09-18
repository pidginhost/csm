package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pidginhost/csm/internal/atomicio"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

const netblockHistoryFile = "netblock_history.json"

// netblockHistoryPruneEvery bounds how often aged entries are rewritten out of
// the history file. Counting ignores them either way, and the file would
// otherwise be rewritten on nearly every cycle as entries cross the window.
const netblockHistoryPruneEvery = time.Hour

// netblockHistory remembers when each address was last seen blocked, so a
// subnet that rotates through addresses one block at a time still reaches
// the netblock threshold. Subnets records when each subnet was last blocked:
// only offenders seen after that count toward the next subnet block.
type netblockHistory struct {
	IPs      map[string]time.Time `json:"ips"`
	Subnets  map[string]time.Time `json:"subnets,omitempty"`
	PrunedAt time.Time            `json:"pruned_at,omitempty"`
}

func loadNetblockHistory(statePath string) *netblockHistory {
	h := &netblockHistory{}
	path := filepath.Join(statePath, netblockHistoryFile)
	if data, err := osFS.ReadFile(path); err == nil {
		if uerr := json.Unmarshal(data, h); uerr != nil {
			fmt.Fprintf(os.Stderr, "autoblock: %s is corrupt, ignoring netblock history: %v\n", path, uerr)
			h = &netblockHistory{}
		}
	}
	if h.IPs == nil {
		h.IPs = make(map[string]time.Time)
	}
	if h.Subnets == nil {
		h.Subnets = make(map[string]time.Time)
	}
	return h
}

func saveNetblockHistory(statePath string, h *netblockHistory) {
	path := filepath.Join(statePath, netblockHistoryFile)
	if err := atomicio.AtomicWriteJSON(path, 0o600, h); err != nil {
		fmt.Fprintf(os.Stderr, "autoblock: persist %s failed: %v\n", path, err)
	}
}

// ForgetNetblockHistory drops an address the operator cleared, so a false
// positive does not keep counting toward a block of its whole subnet.
func ForgetNetblockHistory(statePath, ip string) {
	work := autoBlockQueues.acquire()
	defer work.finish()
	work.progress()
	h := loadNetblockHistory(statePath)
	if _, ok := h.IPs[ip]; ok {
		delete(h.IPs, ip)
		saveNetblockHistory(statePath, h)
	}
	work.complete()
}

// netblockWindow resolves the counting window. Load fills the default and
// validation rejects anything unparseable, so the fallback only covers a
// Config assembled in code.
func netblockWindow(cfg *config.Config) time.Duration {
	return parseExpiryWithDefault(cfg.AutoResponse.NetBlockWindow, config.DefaultNetBlockWindow)
}

// recordNetblockHistory notes every address blocked right now: tracker
// entries with their block times, and addresses only the live kernel set
// knows (operator and permanent blocks), stamped when first seen. It reports
// whether the history changed.
func recordNetblockHistory(h *netblockHistory, tracked []blockedIP, current map[string]bool, now time.Time, window time.Duration) bool {
	changed := false
	note := func(ip string, at time.Time) {
		if prev, ok := h.IPs[ip]; !ok || at.After(prev) {
			h.IPs[ip] = at
			changed = true
		}
	}
	inTracker := make(map[string]bool, len(tracked))
	for _, b := range tracked {
		inTracker[b.IP] = true
		note(b.IP, b.BlockedAt)
	}
	for ip := range current {
		if !inTracker[ip] {
			if _, ok := h.IPs[ip]; !ok {
				note(ip, now)
			}
		}
	}
	if now.Sub(h.PrunedAt) >= netblockHistoryPruneEvery {
		for ip, at := range h.IPs {
			if !current[ip] && now.Sub(at) > window {
				delete(h.IPs, ip)
			}
		}
		for cidr, at := range h.Subnets {
			if now.Sub(at) > window {
				delete(h.Subnets, cidr)
			}
		}
		h.PrunedAt = now
		changed = true
	}
	return changed
}

// currentlyBlocked is every address blocked right now, from the tracker and
// from the live kernel set when the engine can list it.
func currentlyBlocked(tracked []blockedIP, live firewall.LiveBlockedSnapshot, useLive bool) map[string]bool {
	current := make(map[string]bool, len(tracked)+len(live.V4)+len(live.V6))
	for _, b := range tracked {
		current[b.IP] = true
	}
	if useLive {
		for _, set := range []map[string]struct{}{live.V4, live.V6} {
			for ip := range set {
				current[ip] = true
			}
		}
	}
	return current
}

// netblockCounts groups addresses by subnet: every address blocked now, and
// every address whose block ended inside the window. A block that is still in
// place counts however long ago it began. Addresses the firewall now allows
// are no longer evidence.
func netblockCounts(cfg *config.Config, h *netblockHistory, current map[string]bool, blocker IPBlocker, now time.Time, window time.Duration) map[string]int {
	allow, _ := blocker.(allowChecker)
	counts := make(map[string]int)
	for ip, at := range h.IPs {
		if !current[ip] && now.Sub(at) > window {
			continue
		}
		cidr := subnetEscalationCIDR(ip)
		// Exempt IPs do not contribute toward the netblock threshold so that
		// a cluster of blocked addresses inside an operator-declared DoS-exempt
		// range cannot inadvertently auto-block that range as a subnet.
		if cidr == "" || cidrIntersectsDOSExempt(cfg, cidr) {
			continue
		}
		// Ended blocks that an earlier subnet block already answered must
		// not re-block the subnet for the rest of the window. Blocks still
		// in place count as before.
		if last, ok := h.Subnets[cidr]; ok && !current[ip] && !at.After(last) {
			continue
		}
		if allow != nil && allow.IsAllowed(ip) {
			continue
		}
		counts[cidr]++
	}
	return counts
}
