package daemon

import (
	"fmt"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// consumeAppliedBlocks consumes verified outcomes before their audit ack.
// A failed state read is not proof of removal; leave the outbox pending.
func (d *Daemon) consumeAppliedBlocks(rows []admission.AuditRow) error {
	state, err := firewall.LoadState(d.currentCfg().StatePath)
	if err != nil {
		return fmt.Errorf("reading verified firewall state for applied blocks: %w", err)
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
	tdb, adb := checks.GetThreatDB(), attackdb.Global()
	for _, r := range rows {
		addr, ok := r.Target.Addr()
		if !ok {
			continue
		}
		ip := addr.String()
		if adb != nil {
			adb.MarkBlocked(ip)
		}
		b, exists := standing[string(r.Attempt.ID)]
		if tdb != nil && exists && b.IP == ip && b.ExpiresAt.Equal(r.ExpiresAt) {
			entries = append(entries, store.PermanentBlockEntry{IP: ip, Reason: b.Reason, ExpiresAt: b.ExpiresAt})
		}
	}
	if tdb != nil {
		if err := tdb.AddTemporaryBatch(entries); err != nil {
			return fmt.Errorf("recording applied threat batch: %w", err)
		}
	}
	return nil
}
