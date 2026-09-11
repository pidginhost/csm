package checks

import (
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

// The state-call gate serializes real cleanup. Its separate metadata mutex
// keeps health available while filesystem and database operations are blocked.
type autoBlockCleanupQueue struct {
	path                                    string
	records                                 map[string]*autoBlockCleanupRecord
	sources                                 map[string]bool
	blockSources                            map[string]map[autoBlockCleanupBlock]bool
	depthKnown, historyUnknown, lowerBound  bool
	readFailed, writeFailed, snapshotFailed bool
	loss                                    *queuehealth.Tracker
}

type autoBlockCleanupRecord struct {
	at                                     time.Time
	inFlight, completed, failed, lossKnown bool
	blocks                                 map[autoBlockCleanupBlock]bool
	blocksKnown                            bool
}

type autoBlockCleanupBlock struct {
	blockedAt, expiresAt time.Time
}

type autoBlockCleanupCycle struct {
	entries map[string]*autoBlockCleanupRecord
	settled bool
}

func newAutoBlockCleanupQueue() *autoBlockCleanupQueue {
	return &autoBlockCleanupQueue{
		records: make(map[string]*autoBlockCleanupRecord),
		loss:    queuehealth.New(0, time.Minute),
	}
}

func (c *autoBlockCleanupQueue) setPath(path string) {
	if c.path == path {
		return
	}
	c.path = path
	clear(c.records)
	c.sources = nil
	c.blockSources = nil
	c.depthKnown, c.historyUnknown = false, false
	c.readFailed, c.writeFailed, c.snapshotFailed = false, false, false
}

func (c *autoBlockCleanupQueue) record(ip string, known bool) *autoBlockCleanupRecord {
	r := c.records[ip]
	if r == nil {
		r = &autoBlockCleanupRecord{at: time.Now(), lossKnown: known}
		c.records[ip] = r
	}
	return r
}

func (w *autoBlockStateWork) beginCleanup(path string, ips []string, snapshotErr error) {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	c := q.cleanup
	c.setPath(path)
	c.snapshotFailed = snapshotErr != nil
	c.lowerBound = c.lowerBound || snapshotErr != nil
	w.cleanupCycle = &autoBlockCleanupCycle{entries: make(map[string]*autoBlockCleanupRecord)}
	for _, ip := range ips {
		r := c.record(ip, true)
		// A live engine entry is new cleanup demand even if an earlier
		// completed cleanup left its retry marker after a failed save.
		r.completed, r.lossKnown = false, true
		w.cleanupCycle.entries[ip] = r
	}
}

func (w *autoBlockStateWork) admitCleanup(ip string) {
	w.queue.mu.Lock()
	c := w.queue.cleanup
	r := c.record(ip, !c.historyUnknown)
	blocks := c.blockSources[ip]
	if c.depthKnown && r.blocksKnown {
		for version := range blocks {
			if !r.blocks[version] {
				r.completed, r.lossKnown = false, true
				break
			}
		}
	}
	// Each snapshot owns its immutable source set. Retain only the latest
	// cleanup's generations, rather than accumulating every earlier block.
	r.blocks = blocks
	r.blocksKnown = c.depthKnown
	w.cleanupCycle.entries[ip] = r
	w.queue.mu.Unlock()
}

func (w *autoBlockStateWork) startCleanup(ip string) {
	w.queue.mu.Lock()
	w.cleanupCycle.entries[ip].inFlight = true
	w.at = time.Now()
	w.queue.mu.Unlock()
}

func (w *autoBlockStateWork) cleanupOutcome(ip string, failed bool) {
	w.queue.mu.Lock()
	r := w.cleanupCycle.entries[ip]
	r.completed = r.completed || !failed
	r.failed = failed
	w.queue.mu.Unlock()
}

func (w *autoBlockStateWork) observeCleanupState(state *blockState, settle bool) {
	c := w.queue.cleanup
	sources := make(map[string]bool, len(state.IPs)+len(state.CleanupPending))
	blocks := make(map[string]map[autoBlockCleanupBlock]bool, len(state.IPs))
	for _, b := range state.IPs {
		sources[b.IP] = true
		if blocks[b.IP] == nil {
			blocks[b.IP] = make(map[autoBlockCleanupBlock]bool)
		}
		blocks[b.IP][autoBlockCleanupBlock{b.BlockedAt.UTC(), b.ExpiresAt.UTC()}] = true
	}
	for _, ip := range state.CleanupPending {
		sources[ip] = true
		c.record(ip, !c.historyUnknown)
	}
	c.sources = sources
	c.blockSources = blocks
	c.depthKnown = true
	for ip, r := range c.records {
		if !r.blocksKnown {
			// First rediscovery establishes a baseline, not fresh demand.
			// Keep it until the next cleanup can distinguish newer blocks.
			r.blocks, r.blocksKnown = blocks[ip], true
		}
	}
	w.settleCleanupRecords(settle)
}

func (w *autoBlockStateWork) settleCleanupRecords(settle bool) {
	c := w.queue.cleanup
	for ip, r := range c.records {
		active := w.cleanupCycle != nil && w.cleanupCycle.entries[ip] == r
		if !c.sources[ip] && (settle || !active) {
			if !r.completed && r.lossKnown {
				c.loss.Lose(time.Now(), 1)
			}
			delete(c.records, ip)
		} else if settle {
			r.inFlight = false
		}
	}
}

func (w *autoBlockStateWork) forgetCleanupState() {
	c := w.queue.cleanup
	c.sources = nil
	c.blockSources = nil
	c.depthKnown, c.historyUnknown, c.lowerBound = false, true, true
	for ip, r := range c.records {
		if w.cleanupCycle != nil && w.cleanupCycle.entries[ip] != r {
			delete(c.records, ip)
		}
	}
}

func (w *autoBlockStateWork) finishCleanupLocked() {
	c := w.queue.cleanup
	switch {
	case w.readingState:
		c.readFailed = true
		w.forgetCleanupState()
	case w.retryCycle != nil && w.retryCycle.saving && !w.retryCycle.settled:
		c.writeFailed = true
		w.forgetCleanupState()
	}
	if w.cleanupCycle == nil {
		return
	}
	if !w.completed {
		for _, r := range w.cleanupCycle.entries {
			if r.inFlight && !r.completed {
				r.failed = true
			}
		}
	}
	if w.cleanupCycle.settled {
		return
	}
	if c.depthKnown {
		w.settleCleanupRecords(true)
	} else {
		// Keep only the last observed batch across uncertainty so a later
		// tracker read can recover its retry sources and acknowledgments.
		for _, r := range c.records {
			r.inFlight = false
		}
	}
}

func (c *autoBlockCleanupQueue) status(now time.Time, active *autoBlockStateWork) queuehealth.Status {
	row := c.loss.Snapshot(now)
	row.CapacityUnavailable = true
	row.DepthUnavailable = !c.depthKnown
	row.DroppedLowerBound = c.lowerBound
	row.LagBasis = "deferred_checkpoint"
	if active != nil && active.cleanupCycle != nil && len(c.records) > 0 {
		row.ProcessingSeconds = max(0, now.Sub(active.at).Seconds())
	}
	failed := false
	for ip, r := range c.records {
		if r.inFlight {
			row.InFlight++
		} else if c.depthKnown || active != nil && active.cleanupCycle != nil && active.cleanupCycle.entries[ip] == r {
			row.Depth++
			row.LagSeconds = max(row.LagSeconds, now.Sub(r.at).Seconds())
		}
		failed = failed || r.failed
	}
	switch {
	case c.readFailed || c.writeFailed || c.snapshotFailed:
		row.Status, row.Reason = "degraded", "state_io"
	case failed:
		row.Status, row.Reason = "degraded", "retry_failed"
	case row.ProcessingSeconds >= time.Minute.Seconds():
		row.Status, row.Reason = "degraded", "processing_lag"
	}
	return row
}
