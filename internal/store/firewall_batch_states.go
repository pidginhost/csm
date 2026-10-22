package store

import (
	"encoding/json"
	"net/netip"

	"github.com/pidginhost/csm/internal/firewall"
)

// validateFirewallBatchStates holds a batch of two or more members to the
// only change it may make: each member adds its own row, and every other row
// stays as it was. Nothing evicts for a batch, so only a verified row that
// had expired when the batch was planned may be missing from its After state.
func validateFirewallBatchStates(a firewall.FirewallAction) error {
	if !sameFirewallRows(a.Before.BlockedNet, a.After.BlockedNet) || !sameFirewallRows(a.Before.Allowed, a.After.Allowed) || !sameFirewallRows(a.Before.PortAllowed, a.After.PortAllowed) {
		return errInvalidFirewallManifest
	}
	kept := map[string]int{}
	beforeRows := make([]string, 0, len(a.Before.Blocked))
	for _, row := range a.Before.Blocked {
		raw, err := json.Marshal(row)
		if err != nil {
			return errInvalidFirewallManifest
		}
		key := string(raw)
		kept[key]++
		beforeRows = append(beforeRows, key)
	}
	members := map[string]firewall.ActionRequest{}
	targets := map[string]bool{}
	seen := map[string]bool{}
	for _, m := range a.Members {
		members[m.Request.ID] = m.Request
		targets[m.Request.Target] = true
	}
	nextBefore := 0
	for _, row := range a.After.Blocked {
		raw, err := json.Marshal(row)
		if err != nil {
			return errInvalidFirewallManifest
		}
		if kept[string(raw)] > 0 {
			// Address aliases can carry different decisions. Their order
			// determines which decision the engine's lookups select.
			for nextBefore < len(beforeRows) && beforeRows[nextBefore] != string(raw) {
				if !firewallRowExpired(a.Before.Blocked[nextBefore], a) {
					return errInvalidFirewallManifest
				}
				nextBefore++
			}
			if nextBefore == len(beforeRows) {
				return errInvalidFirewallManifest
			}
			nextBefore++
			kept[string(raw)]--
			if !firewallRowExpired(row, a) && targets[canonicalFirewallTarget(row.IP)] {
				return errInvalidFirewallManifest
			}
			continue
		}
		m, ok := members[row.ActionID]
		if seen[row.ActionID] {
			return errInvalidFirewallManifest
		}
		if !ok || row.IP != m.Target || row.Reason != m.Reason || row.Unverified || !row.ExpiresAt.Equal(row.BlockedAt.Add(m.TTL)) || !row.ExpiresAt.After(a.CreatedAt) {
			return errInvalidFirewallManifest
		}
		seen[row.ActionID] = true
	}
	if len(seen) != len(members) {
		return errInvalidFirewallManifest
	}
	for _, row := range a.Before.Blocked[nextBefore:] {
		if !firewallRowExpired(row, a) {
			return errInvalidFirewallManifest
		}
	}
	return nil
}

func firewallRowExpired(row firewall.BlockedEntry, a firewall.FirewallAction) bool {
	// Expiry cannot settle an unknown kernel effect; its owner must do so.
	return !row.Unverified && !row.ExpiresAt.IsZero() && !row.ExpiresAt.After(a.CreatedAt)
}

// canonicalFirewallTarget compares a stored row's address with a member's
// canonical target, whatever spelling an older row used.
func canonicalFirewallTarget(ip string) string {
	if addr, err := netip.ParseAddr(ip); err == nil {
		return addr.Unmap().String()
	}
	return ip
}

func sameFirewallRows[T any](a, b []T) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	return err == nil && string(left) == string(right)
}
