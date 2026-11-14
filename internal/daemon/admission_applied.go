package daemon

import (
	"errors"
	"fmt"
	"sync"

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
	var standing []checks.AdmissionBlock
	writeErr := tdb.AddTemporaryBatchFrom(func() []store.PermanentBlockEntry {
		standing, readErr = d.standingAppliedBlocks(rows)
		entries := make([]store.PermanentBlockEntry, 0, len(standing))
		for _, b := range standing {
			entries = append(entries, store.PermanentBlockEntry{IP: b.IP, Reason: b.Reason, ExpiresAt: b.ExpiresAt})
		}
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
	if !d.appliedBlocks.add(standing) {
		return errors.New("the applied-block consumer is full or stopped")
	}
	return nil
}

// standingAppliedBlocks returns each row whose action's verified firewall
// row still stands at the row's address and expiry, as that row records it.
func (d *Daemon) standingAppliedBlocks(rows []admission.AuditRow) ([]checks.AdmissionBlock, error) {
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
	var blocks []checks.AdmissionBlock
	for _, r := range rows {
		addr, ok := r.Target.Addr()
		if !ok {
			continue
		}
		ip := addr.String()
		b, exists := standing[string(r.Attempt.ID)]
		if exists && b.IP == ip && b.ExpiresAt.Equal(r.ExpiresAt) {
			blocks = append(blocks, checks.AdmissionBlock{IP: ip, Reason: b.Reason, Check: r.Check, FindingID: r.FindingID, BlockedAt: b.BlockedAt, ExpiresAt: b.ExpiresAt})
		}
	}
	return blocks, nil
}

// appliedBlockQueue hands applied admission blocks to the legacy consumers
// (tracker row, permanent-block strike, the auto_block finding) in order, on
// a daemon goroutine: the tracker's lock can be held for a whole scan, and
// the admission owner must not wait for it. Delivery is best effort: blocks
// still queued when the daemon stops are not recorded there.
type appliedBlockQueue struct {
	mu      sync.Mutex
	pending []checks.AdmissionBlock
	wake    chan struct{}
	stopped bool
}

// add never waits for consumers. A full or stopped queue refuses the batch,
// which leaves the durable audit delivery unacknowledged, so the owner
// retries it and the next start redelivers what shutdown left. Shutdown
// discards only work already queued.
func (q *appliedBlockQueue) add(blocks []checks.AdmissionBlock) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(blocks) == 0 {
		return true
	}
	if q.stopped {
		return false
	}
	if len(blocks) > int(admission.MaxAuditSlots)-len(q.pending) {
		return false
	}
	q.pending = append(q.pending, blocks...)
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return true
}

// serve records queued blocks until stop closes.
func (q *appliedBlockQueue) serve(d *Daemon, stop <-chan struct{}) {
	defer func() {
		q.mu.Lock()
		q.stopped, q.pending = true, nil
		q.mu.Unlock()
	}()
	for {
		select {
		case <-stop:
			return
		default:
		}
		q.mu.Lock()
		blocks := q.pending
		q.pending = nil
		q.mu.Unlock()
		if len(blocks) > 0 {
			d.recordAppliedBlocks(checks.RecordAdmissionBlocks(d.currentCfg(), blocks))
		}
		select {
		case <-q.wake:
		case <-stop:
			return
		}
	}
}
