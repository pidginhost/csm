//go:build linux

package firewall

import "errors"

// errDurableBlockRows refuses batch row changes while a durable lifecycle
// owns the state: its batch manifest is not built yet.
var errDurableBlockRows = errors.New("firewall state is owned by the durable lifecycle")

// ErrBlockBatchState requires the owner to hold automatic execution while
// the engine's state safety changes lack a durable acknowledgement.
var ErrBlockBatchState = errors.New("firewall batch state is unproven")

func unverifiedRows(entries []BlockedEntry) int {
	n := 0
	for _, entry := range entries {
		if entry.Unverified {
			n++
		}
	}
	return n
}

// MarkBlockActionsUnverified flags the rows written by the named attempts
// as unproven, in one state write, and reports how many changed. Startup
// calls it with the ledger's unresolved attempts before Apply, so their
// rows are neither restored nor reported as blocks. While a failed state
// write holds batches it writes the safe state even when nothing is named,
// and a successful write releases the hold.
func (e *Engine) MarkBlockActionsUnverified(actions []string) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lifecycle != nil {
		return 0, errDurableBlockRows
	}
	named := make(map[string]bool, len(actions))
	for _, id := range actions {
		if id != "" {
			named[id] = true
		}
	}
	held := e.blockBatchStateErr != nil
	if len(named) == 0 && !held {
		return 0, nil
	}
	state, ok := e.loadStateFileRawLocked()
	if !ok {
		e.blockBatchStateErr = errors.Join(ErrBlockBatchState, errors.New("firewall state unavailable"))
		return 0, e.blockBatchStateErr
	}
	marked := 0
	pending := false
	for i, entry := range state.Blocked {
		if named[entry.ActionID] && !entry.Unverified {
			state.Blocked[i].Unverified = true
			marked++
		}
		if named[entry.ActionID] && e.unverifiedBlockActions[entry.ActionID] {
			pending = true
		}
	}
	if marked == 0 && !pending && !held {
		return 0, nil
	}
	e.rememberUnverifiedBlockActionsLocked(state)
	if err := e.saveState(&state); err != nil {
		e.blockBatchStateErr = errors.Join(ErrBlockBatchState, err)
		return marked, e.blockBatchStateErr
	}
	return marked, nil
}

// The in-memory mark survives a failed save and cache replacement until a
// successful full-state write records it. Only then can the hold clear.
func (e *Engine) rememberUnverifiedBlockActionsLocked(state FirewallState) {
	if e.unverifiedBlockActions == nil {
		e.unverifiedBlockActions = make(map[string]bool)
	}
	for _, row := range state.Blocked {
		if row.Unverified && row.ActionID != "" {
			e.unverifiedBlockActions[row.ActionID] = true
		}
	}
	if e.stateCache != nil {
		e.overlayUnverifiedBlockActionsLocked(e.stateCache)
		e.rebuildIndexLocked()
	}
}

func (e *Engine) suppressFailedBlockActionsLocked(actions []string) {
	if e.failedBlockActions == nil {
		e.failedBlockActions = make(map[string]bool)
	}
	for _, id := range actions {
		if id != "" {
			e.failedBlockActions[id] = true
		}
	}
	if e.stateCache != nil {
		e.overlayUnverifiedBlockActionsLocked(e.stateCache)
		e.rebuildIndexLocked()
	}
}

func (e *Engine) overlayUnverifiedBlockActionsLocked(state *FirewallState) {
	blocked := state.Blocked[:0]
	for _, row := range state.Blocked {
		if e.failedBlockActions[row.ActionID] {
			continue
		}
		if e.unverifiedBlockActions[row.ActionID] {
			row.Unverified = true
		}
		blocked = append(blocked, row)
	}
	state.Blocked = blocked
}
