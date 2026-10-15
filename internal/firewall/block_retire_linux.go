//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"net/netip"
)

// RemoveBlockActionRows removes, in one state write, the rows the named
// attempts wrote and reports how many went. Startup calls it with the
// ledger's settled attempts (failed, or retired after their expiry) once
// every unproven one is marked: nothing they applied can remain, so their
// rows only hold an address. An error reports no completed removal; the
// next start reads the saved state and tries again.
func (e *Engine) RemoveBlockActionRows(actions []string) (int, error) {
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
	if len(named) == 0 {
		return 0, nil
	}
	state, ok := e.loadStateFileRawLocked()
	if !ok {
		return 0, errors.New("firewall state unavailable")
	}
	kept := state.Blocked[:0]
	removed := 0
	for _, row := range state.Blocked {
		if named[row.ActionID] {
			removed++
			continue
		}
		kept = append(kept, row)
	}
	if removed == 0 {
		return 0, nil
	}
	if err := e.checkpointBlockRemovalLocked(); err != nil {
		return 0, err
	}
	state.Blocked = kept
	if err := e.saveState(&state); err != nil {
		return 0, err
	}
	e.forgetBlockActionsLocked(named)
	return removed, nil
}

// RetireBlockActions reports, for each unknown attempt the owner would
// retire after its expiry, whether nothing it may have applied can remain
// in the kernel (spec 5.4): its address has no element, or the element
// belongs to a verified row of another action. Each clear attempt's own row
// (same action ID and address) goes in one state write, under the same
// engine lock as the snapshot, so no batch writes the address in between.
// An element still there otherwise keeps the attempt held, as after a
// forward wall step that made its expiry look past. An error answers
// nothing.
func (e *Engine) RetireBlockActions(actions []BlockAction) ([]bool, error) {
	if len(actions) > MaxBlockBatchMembers {
		return nil, fmt.Errorf("a retirement checks at most %d attempts", MaxBlockBatchMembers)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lifecycle != nil {
		return nil, errDurableBlockRows
	}
	if err := e.checkpointBlockRemovalLocked(); err != nil {
		return nil, err
	}
	snap, err := e.blockSnapshotLocked()
	if err != nil {
		return nil, err
	}
	out := make([]bool, len(actions))
	gone := make(map[BlockAction]bool, len(actions))
	for i, m := range actions {
		addr, ipErr := netip.ParseAddr(m.IP)
		if ipErr != nil {
			return nil, fmt.Errorf("retiring %s: %w", m.Action, ipErr)
		}
		ip := addr.WithZone("").Unmap().String()
		observed, live := snap.live[ip]
		row, held := snap.blocked[stateIPKey(ip)]
		if live && (!held || row.ActionID == m.Action || !snap.proves(row, observed, live)) {
			continue
		}
		out[i] = true
		gone[BlockAction{Action: m.Action, IP: stateIPKey(ip)}] = true
	}
	next := copyFirewallState(snap.prior)
	kept := next.Blocked[:0]
	for _, row := range next.Blocked {
		if gone[BlockAction{Action: row.ActionID, IP: retirementIPKey(row.IP)}] {
			continue
		}
		kept = append(kept, row)
	}
	if len(kept) == len(next.Blocked) {
		return out, nil
	}
	next.Blocked = kept
	if err = e.saveState(&next); err != nil {
		return nil, err
	}
	return out, nil
}

// forgetBlockActionsLocked drops the in-memory marks of attempts whose rows
// are gone.
func (e *Engine) forgetBlockActionsLocked(actions map[string]bool) {
	for id := range actions {
		delete(e.unverifiedBlockActions, id)
		delete(e.failedBlockActions, id)
	}
}

// Recovery compares addresses in the engine's namespace; a legacy row's
// textual zone does not change the address stored in the blocked set.
func retirementIPKey(raw string) string {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return raw
	}
	return addr.WithZone("").Unmap().String()
}

// Preserve the lease proof before dropping rows or authorizing retirement.
// A fresh startup engine must resume the old checkpoint before replacing it.
func (e *Engine) checkpointBlockRemovalLocked() error {
	if err := e.resumeLeaseLocked(); err != nil {
		// Cleanup retries must not treat a failed read as a completed resume.
		e.leaseResumed = false
		return fmt.Errorf("resuming removal lease: %w", err)
	}
	if err := e.saveLeaseLocked(); err != nil {
		return fmt.Errorf("saving removal lease: %w", err)
	}
	return nil
}
