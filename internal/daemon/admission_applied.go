package daemon

import (
	"fmt"
	"time"

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
	var entries []store.PermanentBlockEntry
	var readErr error
	choose := func() []store.PermanentBlockEntry {
		entries, readErr = d.standingAppliedBlocks(rows)
		return entries
	}
	var writeErr error
	if tdb := checks.GetThreatDB(); tdb != nil {
		writeErr = tdb.AddTemporaryBatchFrom(choose)
	} else {
		choose()
	}
	if readErr != nil {
		return readErr
	}
	if writeErr != nil {
		return fmt.Errorf("recording applied threat batch: %w", writeErr)
	}
	if adb := attackdb.Global(); adb != nil {
		for _, entry := range entries {
			if time.Now().Before(entry.ExpiresAt) {
				adb.MarkBlocked(entry.IP)
			}
		}
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
