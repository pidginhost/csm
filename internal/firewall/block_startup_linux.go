//go:build linux

package firewall

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// BlockActionIDsForStartup includes every saved row that can hold an address:
// LoadState hides unverified rows and their address aliases, but removing a
// settled hold can expose another action at that address. An expired row
// no earlier start marked is never restored and is left to expiry, so it
// cannot hold back another block at its address.
func (e *Engine) BlockActionIDsForStartup() ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// #nosec G304 -- filepath.Join under operator-configured statePath.
	data, err := os.ReadFile(filepath.Join(e.statePath, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state FirewallState
	if err = json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	var ids []string
	seen := make(map[string]bool)
	// Apply must retain this expiry decision if the wall clock moves back
	// before installation, or it could restore an action the ledger never saw.
	now := e.leaseNowLocked()
	for _, row := range state.Blocked {
		expired := !row.ExpiresAt.IsZero() && !row.ExpiresAt.After(now)
		if row.ActionID != "" && !seen[row.ActionID] && (row.Unverified || !expired) {
			seen[row.ActionID] = true
			ids = append(ids, row.ActionID)
		}
	}
	return ids, nil
}
