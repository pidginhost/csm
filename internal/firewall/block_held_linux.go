//go:build linux

package firewall

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// HeldBlockActions reports, for each verified admission block, whether
// what it applied may remain in the kernel: retirement's answer reversed
// (spec 5.4), with no state write. An element still at the address that
// no other action's verified row proves answers held, even after a
// forward wall step makes the block's own row look expired, and so does
// an address whose family the snapshot cannot read; only a removal
// answers false. An error answers nothing.
func (e *Engine) HeldBlockActions(actions []BlockAction) ([]bool, error) {
	if len(actions) > MaxHeldBlockActions {
		return nil, fmt.Errorf("a held check names at most %d blocks", MaxHeldBlockActions)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	canonical, unread, err := e.canonicalBlockActions(actions, "checking")
	if err != nil {
		return nil, err
	}
	if e.blockBatchesHeld {
		return nil, ErrConfirmPending
	}
	snap, err := e.readBlockSnapshotLocked(e.readHeldStateLocked)
	if err != nil {
		return nil, err
	}
	held := clearBlockActions(snap, canonical, unread)
	for i := range held {
		held[i] = !held[i]
	}
	return held, nil
}

// The ordinary raw loader may rename unreadable state for recovery. A
// held check must leave it untouched and keep refusing subsequent reads.
func (e *Engine) readHeldStateLocked() (FirewallState, bool) {
	if e.stateAsideErr != nil {
		return FirewallState{}, false
	}
	// #nosec G304 -- filepath.Join under operator-configured statePath.
	data, err := os.ReadFile(filepath.Join(e.statePath, "state.json"))
	if err != nil {
		return FirewallState{}, os.IsNotExist(err)
	}
	var state FirewallState
	err = json.Unmarshal(data, &state)
	return state, err == nil
}
