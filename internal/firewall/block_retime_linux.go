//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// RetimeBlocks replaces the elements of the blocked address sets with the
// ones the saved rows give, in one transaction: each timed block gets the
// time its row has left. A ruleset restored from a dump gives a timed
// block the time it had left when the dump was taken, so the block would
// outlast its row by the dump's age and no row would prove its element.
// As at Apply, a row held back as unverified gets no element and an
// element no row names goes. Nothing is sent when the rows could not be
// read, or under the durable lifecycle, which changes the kernel only
// through its own actions. The transaction has its own connection, so one
// that cannot be finished is dropped whole.
func (e *Engine) RetimeBlocks() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lifecycle != nil {
		return nil
	}
	if e.setBlocked == nil {
		return errors.New("blocked sets unavailable")
	}
	conn, err := newLifecycleConn(e)
	if err != nil {
		return err
	}
	if e.stateAsideErr != nil {
		return e.stateAsideErr
	}
	// Missing state after preservation is not proof of an empty policy.
	if e.stateSetAside != "" {
		if _, err := os.Stat(filepath.Join(e.statePath, "state.json")); err != nil {
			return fmt.Errorf("checking preserved firewall state: %w", err)
		}
	}
	state, readable := e.loadStateFileRawLocked()
	if !readable {
		return errors.Join(errors.New("firewall state unreadable"), e.stateAsideErr)
	}
	e.overlayUnverifiedBlockActionsLocked(&state)
	normalizeFirewallStateIPs(&state)
	initial := e.initialBlockStateFromRowsLocked(state, e.expiryNow())
	conn.FlushSet(e.setBlocked)
	if err := addElementsChunked(conn, e.setBlocked, initial.blocked4); err != nil {
		return err
	}
	// A set an earlier ruleset left behind is not in the kernel.
	if e.setBlocked6 != nil && e.cfg.IPv6 {
		conn.FlushSet(e.setBlocked6)
		if err := addElementsChunked(conn, e.setBlocked6, initial.blocked6); err != nil {
			return err
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("retiming blocked sets: %w", err)
	}
	return nil
}
