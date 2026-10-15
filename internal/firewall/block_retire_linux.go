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
	if len(named) == 0 && !e.blockRemovalPending {
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
	if removed == 0 && !e.blockRemovalPending {
		return 0, nil
	}
	if err := e.checkpointBlockRemovalLocked(); err != nil {
		return 0, err
	}
	state.Blocked = kept
	e.overlayUnverifiedBlockActionsLocked(&state)
	if err := e.saveBlockRemovalLocked(state); err != nil {
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
// forward wall step that made its expiry look past, and so does an address
// whose family the snapshot cannot read. An error answers nothing.
func (e *Engine) RetireBlockActions(actions []BlockAction) ([]bool, error) {
	if len(actions) > MaxBlockBatchMembers {
		return nil, fmt.Errorf("a retirement checks at most %d attempts", MaxBlockBatchMembers)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lifecycle != nil {
		return nil, errDurableBlockRows
	}
	canonical := make([]BlockAction, len(actions))
	unread := make([]bool, len(actions))
	for i, m := range actions {
		addr, err := netip.ParseAddr(m.IP)
		if err != nil {
			return nil, fmt.Errorf("retiring %s: %w", m.Action, err)
		}
		addr = addr.WithZone("").Unmap()
		// The snapshot skips a missing or disabled IPv6 set, so it cannot
		// prove such an address absent; the rest of the batch still answers.
		unread[i] = addr.Is6() && (!e.cfg.IPv6 || e.setBlocked6 == nil)
		canonical[i] = BlockAction{Action: m.Action, IP: addr.String()}
	}
	if err := e.checkpointBlockRemovalLocked(); err != nil {
		return nil, err
	}
	snap, err := e.blockSnapshotLocked()
	if err != nil {
		return nil, err
	}
	owners := make(map[string][]string)
	for _, row := range snap.prior.Blocked {
		ip := retirementIPKey(row.IP)
		observed, live := snap.live[ip]
		if snap.proves(row, observed, live) {
			owners[ip] = append(owners[ip], row.ActionID)
		}
	}
	out := make([]bool, len(actions))
	gone := make(map[BlockAction]bool, len(actions))
	for i, m := range canonical {
		if unread[i] {
			continue
		}
		_, live := snap.live[m.IP]
		out[i] = !live
		for _, owner := range owners[m.IP] {
			if owner != m.Action {
				out[i] = true
				break
			}
		}
		if out[i] {
			gone[m] = true
		}
	}
	next := copyFirewallState(snap.prior)
	kept := next.Blocked[:0]
	for _, row := range next.Blocked {
		if gone[BlockAction{Action: row.ActionID, IP: retirementIPKey(row.IP)}] {
			continue
		}
		kept = append(kept, row)
	}
	if len(kept) == len(next.Blocked) && !e.blockRemovalPending {
		return out, nil
	}
	next.Blocked = kept
	if err = e.saveBlockRemovalLocked(next); err != nil {
		return nil, err
	}
	return out, nil
}

// A failed rename durability check can leave no rows for the retry to
// remove. Keep requiring a full state write until one confirms durability.
func (e *Engine) saveBlockRemovalLocked(state FirewallState) error {
	err := e.writeStateLocked(state)
	e.blockRemovalPending = err != nil
	return err
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
