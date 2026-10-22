package firewall

import (
	"encoding/json"
	"time"
)

// RetiredActionState is the committed state an unknown block action retires
// to as expired_unproven (spec 5.4): every member target is timed and expired,
// and every row its Before and After states disagree on is a verified timed
// block that has expired at at. Committed state keeps the rows both
// states agree on. Any other action reports false and waits for an
// operator's Resolve: one that is not a block, changes anything but blocked
// rows, or has an effect that is permanent, unverified or still live.
func RetiredActionState(a FirewallAction, at time.Time) (FirewallState, bool) {
	if at.IsZero() || a.Phase != "unknown" {
		return FirewallState{}, false
	}
	for _, m := range a.ActionMembers() {
		if m.Request.Operation != "block" || m.Request.TTL <= 0 {
			return FirewallState{}, false
		}
		found := false
		for _, row := range a.After.Blocked {
			if sameAddress(row.IP, m.Request.Target) {
				if row.Unverified || row.ExpiresAt.IsZero() || row.ExpiresAt.After(at) {
					return FirewallState{}, false
				}
				found = true
			}
		}
		if !found {
			return FirewallState{}, false
		}
	}
	if a.Request.Operation != "block" || !sameRows(a.Before.Allowed, a.After.Allowed) || !sameRows(a.Before.BlockedNet, a.After.BlockedNet) || !sameRows(a.Before.PortAllowed, a.After.PortAllowed) {
		return FirewallState{}, false
	}
	expired := func(row BlockedEntry) bool {
		return !row.Unverified && !row.ExpiresAt.IsZero() && !row.ExpiresAt.After(at)
	}
	unmatched := make(map[BlockedEntry]int, len(a.After.Blocked))
	for _, row := range a.After.Blocked {
		unmatched[blockedRowKey(row)]++
	}
	state := FirewallState{Allowed: a.Before.Allowed, BlockedNet: a.Before.BlockedNet, PortAllowed: a.Before.PortAllowed}
	for _, row := range a.Before.Blocked {
		if key := blockedRowKey(row); unmatched[key] > 0 {
			unmatched[key]--
			state.Blocked = append(state.Blocked, row)
		} else if !expired(row) {
			return FirewallState{}, false
		}
	}
	for _, row := range a.After.Blocked {
		if key := blockedRowKey(row); unmatched[key] > 0 {
			unmatched[key]--
			if !expired(row) {
				return FirewallState{}, false
			}
		}
	}
	return state, true
}

// blockedRowKey identifies a row by value whatever location its times carry.
func blockedRowKey(row BlockedEntry) BlockedEntry {
	row.BlockedAt, row.ExpiresAt = row.BlockedAt.UTC(), row.ExpiresAt.UTC()
	return row
}

// sameRows compares two lists by value; an empty list and none are equal.
func sameRows[T any](a, b []T) bool {
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
