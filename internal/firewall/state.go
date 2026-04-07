package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// LoadState reads the firewall state file directly without requiring a running engine.
// Used by CLI commands that only need to display state.
// Note: callers that have access to the store package should check store.Global()
// first for bbolt-backed state. This function reads flat-file state.json only.
func LoadState(statePath string) (*FirewallState, error) {
	stateFile := filepath.Join(statePath, "firewall", "state.json")
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

	return &state, nil
}
