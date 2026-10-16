package daemon

import (
	"errors"
	"fmt"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// loadAppliedState lets tests act between the state read and the threat write.
var loadAppliedState = firewall.LoadState

// consumeAppliedBlocks consumes verified outcomes before their audit ack.
// A failed state read is not proof of removal; leave the outbox pending.
// The threat rows are chosen from a state read under the threat writer lock,
// so an unblock that removes the firewall row after that read waits for the
// batch to commit and then removes what it wrote.
func (d *Daemon) consumeAppliedBlocks(rows []admission.AuditRow) error {
	// A destination the daemon has not opened cannot record the block, and
	// acknowledging the rows now would lose their evidence for good.
	tdb, adb := checks.GetThreatDB(), attackdb.Global()
	switch {
	case tdb == nil:
		return errors.New("the threat database is not open yet")
	case adb == nil:
		return errors.New("the attack database is not open yet")
	}
	var readErr error
	writeErr := tdb.AddTemporaryBatchFrom(func() []store.PermanentBlockEntry {
		var entries []store.PermanentBlockEntry
		entries, readErr = d.standingAppliedBlocks(rows)
		return entries
	})
	if readErr != nil {
		return readErr
	}
	// The attack database records that the block applied, as the legacy
	// path marks it at block time: a block removed or expired before
	// delivery is still marked, and the mark does not wait for the threat
	// store.
	for _, r := range rows {
		if addr, ok := r.Target.Addr(); ok {
			adb.MarkBlocked(addr.String())
		}
	}
	if writeErr != nil {
		return fmt.Errorf("recording applied threat batch: %w", writeErr)
	}
	return nil
}

// standingAppliedBlocks returns a threat entry for each row whose action's
// verified firewall row still stands at the row's address and expiry.
func (d *Daemon) standingAppliedBlocks(rows []admission.AuditRow) ([]store.PermanentBlockEntry, error) {
	state, err := loadAppliedState(d.currentCfg().StatePath)
	if err != nil {
		return nil, fmt.Errorf("reading verified firewall state for applied blocks: %w", err)
	}
	standing := make(map[string]firewall.BlockedEntry)
	if state != nil {
		for _, b := range state.Blocked {
			if b.ActionID != "" {
				standing[b.ActionID] = b
			}
		}
	}
	var entries []store.PermanentBlockEntry
	for _, r := range rows {
		addr, ok := r.Target.Addr()
		if !ok {
			continue
		}
		ip := addr.String()
		b, exists := standing[string(r.Attempt.ID)]
		if exists && b.IP == ip && b.ExpiresAt.Equal(r.ExpiresAt) {
			entries = append(entries, store.PermanentBlockEntry{IP: ip, Reason: b.Reason, ExpiresAt: b.ExpiresAt})
		}
	}
	return entries, nil
}
