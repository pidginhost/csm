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
	err := e.saveState(&next)
	if err == nil {
		return nil
	}
	var uncertain *stateDurabilityError
	if !errors.As(err, &uncertain) {
		return err
	}
	if restoreErr := e.saveState(&prior); restoreErr != nil {
		return fmt.Errorf("partial failure: %w (state restore failed: %w)", err, restoreErr)
	}
	return fmt.Errorf("intent write failed; previous state restored: %w", err)
}
