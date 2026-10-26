//go:build linux

package firewall

import (
	"errors"
	"fmt"
)

type stateDurabilityError struct{ cause error }

func (e *stateDurabilityError) Error() string {
	return fmt.Sprintf("state file matches requested change but durability is unconfirmed: %v", e.cause)
}

func (e *stateDurabilityError) Unwrap() error { return e.cause }

// A write can fail after rename made the next state visible. Restore the
// prior intent before returning so background cleanup retains its retry rows.
// Both failures must be exposed if storage also refuses the rollback.
func (e *Engine) persistFirewallIntent(prior, next FirewallState) error {
	return persistFirewallIntentUsing(prior, next, e.saveState)
}

func persistFirewallIntentUsing(prior, next FirewallState, save func(*FirewallState) error) error {
	err := save(&next)
	if err == nil {
		return nil
	}
	var uncertain *stateDurabilityError
	if !errors.As(err, &uncertain) {
		return err
	}
	if restoreErr := save(&prior); restoreErr != nil {
		return fmt.Errorf("partial failure: %w (state restore failed: %w)", err, restoreErr)
	}
	return fmt.Errorf("intent write failed; previous state restored: %w", err)
}

// Admission identity belongs to every saved row, not just the alias that
// wins policy normalization. Preserve those rows on both commit and rollback.
func (e *Engine) saveBlockStateLocked(state *FirewallState) error {
	if !hasAdmissionRows(*state) {
		return e.saveState(state)
	}
	if e.stateAsideErr != nil {
		return e.stateAsideErr
	}
	next := copyFirewallState(*state)
	e.overlayUnverifiedBlockActionsLocked(&next)
	return e.writeStateLocked(next)
}

func (e *Engine) cacheBlockOwnershipLocked(state FirewallState) {
	e.blockOwnershipRows = nil
	if hasAdmissionRows(state) {
		e.blockOwnershipRows = append([]BlockedEntry(nil), state.Blocked...)
	}
}
