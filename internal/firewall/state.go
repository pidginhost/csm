package firewall

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// ErrPermanentBlock requires an explicit unblock before a timed Web UI block.
var ErrPermanentBlock = errors.New("IP is permanently blocked; unblock it explicitly before applying a timed block")

// ErrLongerBlock requires an explicit unblock before shortening a timed block.
var ErrLongerBlock = errors.New("IP has a longer block; unblock it explicitly before shortening its lifetime")

// ErrBlockChanged prevents undo from replacing a later firewall decision.
var ErrBlockChanged = errors.New("block changed since the action; undo is no longer available")

// SameBlockedEntry compares snapshots without relying on time.Time locations.
func SameBlockedEntry(a, b BlockedEntry) bool {
	return a.IP == b.IP && a.Reason == b.Reason && a.Source == b.Source &&
		a.BlockedAt.Equal(b.BlockedAt) && a.ExpiresAt.Equal(b.ExpiresAt)
}

// LoadState reads the authoritative firewall state file directly without requiring
// a running engine. A missing state file is a valid fresh-host state and returns
// an empty FirewallState.
func LoadState(statePath string) (*FirewallState, error) {
	stateFile := filepath.Join(statePath, "firewall", "state.json")
	// #nosec G304 -- filepath.Join under operator-configured statePath.
	data, err := os.ReadFile(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &FirewallState{}, nil
		}
		return nil, err
	}

	var state FirewallState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	// Clean expired entries
	now := time.Now()
	var active []BlockedEntry
	for _, entry := range state.Blocked {
		if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
			active = append(active, entry)
		}
	}
	state.Blocked = active

	var activeNets []SubnetEntry
	for _, entry := range state.BlockedNet {
		if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
			activeNets = append(activeNets, entry)
		}
	}
	state.BlockedNet = activeNets

	var activeAllowed []AllowedEntry
	for _, entry := range state.Allowed {
		if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
			activeAllowed = append(activeAllowed, entry)
		}
	}
	state.Allowed = activeAllowed

	return &state, nil
}
