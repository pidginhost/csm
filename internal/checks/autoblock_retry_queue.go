package checks

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/queuehealth"
)

var persistAutoBlockState = writeBlockState

// All fields use autoBlockQueueMonitor.mu. Disk identities live only as long
// as their records; an unreadable write outcome never accumulates old versions.
type autoBlockRetryQueue struct {
	path                                   string
	disk                                   []pendingIP
	records                                []*autoBlockPendingRecord
	candidates                             map[*autoBlockCandidate]struct{}
	pendingLoss, candidateLoss             *queuehealth.Tracker
	depthKnown, historyUnknown, lowerBound bool
	readFailed, writeFailed                bool
}

type autoBlockPendingRecord struct {
	at                                     time.Time
	inFlight, completed, lossKnown, failed bool
}

type autoBlockCandidate struct {
	at                                         time.Time
	origins                                    []*autoBlockPendingRecord
	queued                                     *autoBlockPendingRecord
	running, completed, finished, failed, lost bool
}

type autoBlockRetryCycle struct {
	saving, settled bool
}

func newAutoBlockRetryQueue() *autoBlockRetryQueue {
	return &autoBlockRetryQueue{
		candidates:    make(map[*autoBlockCandidate]struct{}),
		pendingLoss:   queuehealth.New(maxPendingBlocks, maxPendingAge),
		candidateLoss: queuehealth.New(0, time.Minute),
	}
}

// InitAutoBlockQueueHealth observes existing retries before daemon consumers
// start, including when automatic blocking is disabled. It never changes state.
func InitAutoBlockQueueHealth(statePath string) error {
	work := autoBlockQueues.acquire()
	defer work.finish()
	_, err := work.readState(statePath)
	work.complete()
	return err
}

func (w *autoBlockStateWork) readState(path string) (*blockState, error) {
	w.progress()
	q := w.queue
	q.mu.Lock()
	w.readingState = true
	q.cleanup.setPath(path)
	q.mu.Unlock()
	state, err := readBlockState(path)
	q.mu.Lock()
	defer q.mu.Unlock()
	w.readingState = false
	r := q.retries
	if r.path != path {
		r.path = path
		r.disk, r.records = nil, nil
		r.depthKnown, r.historyUnknown = false, false
		r.readFailed, r.writeFailed = false, false
	}
	w.retryCycle = &autoBlockRetryCycle{}
	q.cleanup.readFailed = err != nil
	r.readFailed = err != nil
	if err != nil {
		w.failLocked()
		r.forgetUncertain()
		w.forgetCleanupState()
	} else {
		r.reconcile(state.Pending, nil, time.Now())
		w.observeCleanupState(state, false)
	}
	return state, err
}

func (w *autoBlockStateWork) loadState(path string) *blockState {
	state, err := w.readState(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "autoblock: %v; ignoring queued blocks\n", err)
		return &blockState{}
	}
	return state
}

type autoBlockPendingKey struct {
	ip, check string
	queuedAt  time.Time
	severity  alert.Severity
}

func pendingRecordKey(p pendingIP) autoBlockPendingKey {
	return autoBlockPendingKey{ip: p.IP, check: p.Check, queuedAt: p.QueuedAt.UTC(), severity: p.Severity}
}

func (r *autoBlockRetryQueue) reconcile(actual, proposed []pendingIP, now time.Time) {
	pool := make(map[autoBlockPendingKey][]*autoBlockPendingRecord, len(r.disk)+len(proposed))
	for _, version := range [][]pendingIP{r.disk, proposed} {
		for _, p := range version {
			if p.queueRecord != nil {
				key := pendingRecordKey(p)
				pool[key] = append(pool[key], p.queueRecord)
			}
		}
	}
	kept := make(map[*autoBlockPendingRecord]bool, len(actual))
	records := make([]*autoBlockPendingRecord, 0, len(actual))
	for i := range actual {
		p := &actual[i]
		record := p.queueRecord
		if record == nil {
			key := pendingRecordKey(*p)
			available := pool[key]
			for len(available) > 0 {
				known := available[0]
				available = available[1:]
				if !kept[known] {
					record = known
					break
				}
			}
			pool[key] = available
		}
		if record == nil {
			at := p.QueuedAt
			if at.IsZero() {
				at = now
			}
			record = &autoBlockPendingRecord{at: at, lossKnown: !r.historyUnknown}
		}
		p.queueRecord = record
		if !p.QueuedAt.IsZero() {
			record.at = p.QueuedAt
		}
		record.inFlight = false
		kept[record] = true
		records = append(records, record)
	}
	// A duplicate coalesced into a retained retry still has an owner. A
	// successful block remains completed even when its record survives rollback.
	for c := range r.candidates {
		survives := kept[c.queued]
		for _, origin := range c.origins {
			survives = survives || kept[origin]
		}
		if c.completed || survives {
			for _, origin := range c.origins {
				if c.completed || !kept[origin] {
					origin.completed = true
				}
			}
		} else if len(c.origins) == 0 && !c.lost {
			r.candidateLoss.Lose(now, 1)
			c.lost = true
		}
		c.finished = true
	}
	for _, old := range r.disk {
		record := old.queueRecord
		if !kept[record] && !record.completed && record.lossKnown {
			r.pendingLoss.Lose(now, 1)
		}
	}
	r.records = records
	r.disk = append([]pendingIP(nil), actual...)
	for i := range r.disk {
		r.disk[i].queueCandidate = nil
	}
	r.depthKnown = true
}

func (r *autoBlockRetryQueue) forgetUncertain() {
	r.disk, r.records = nil, nil
	r.depthKnown, r.historyUnknown, r.lowerBound = false, true, true
	for c := range r.candidates {
		c.finished = true
	}
}

func (w *autoBlockStateWork) beginPending(p pendingIP) {
	w.queue.mu.Lock()
	p.queueRecord.inFlight = true
	w.queue.mu.Unlock()
}

func (w *autoBlockStateWork) completePending(p pendingIP) {
	w.queue.mu.Lock()
	p.queueRecord.completed = true
	w.queue.mu.Unlock()
}

func (w *autoBlockStateWork) candidate(p pendingIP, existing *autoBlockCandidate) *autoBlockCandidate {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	c := existing
	if c == nil {
		at := p.QueuedAt
		if at.IsZero() {
			at = time.Now()
		}
		c = &autoBlockCandidate{at: at}
		q.retries.candidates[c] = struct{}{}
	}
	if p.queueRecord != nil {
		c.origins = append(c.origins, p.queueRecord)
		if p.queueRecord.at.Before(c.at) {
			c.at = p.queueRecord.at
		}
	}
	return c
}

func (w *autoBlockStateWork) startCandidate(c *autoBlockCandidate) {
	w.queue.mu.Lock()
	c.running = true
	w.queue.mu.Unlock()
}

func (w *autoBlockStateWork) candidateOutcome(c *autoBlockCandidate, err error) {
	success := err == nil || errors.Is(err, firewall.ErrIPProtected)
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	c.completed = c.completed || success
	c.failed = !success
	for _, origin := range c.origins {
		origin.completed = origin.completed || success
		origin.failed = !success
	}
}

// A direct source can complete an eligible retry without consuming it from
// the scan queue. Preserve that acknowledgment before secondary bookkeeping.
func (w *autoBlockStateWork) directOutcome(ip string, attemptAt time.Time, err error) {
	if err != nil && !errors.Is(err, firewall.ErrIPProtected) {
		return
	}
	ip = normalizeBlockIP(ip)
	if ip == "" {
		return
	}
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, p := range q.retries.disk {
		if normalizeBlockIP(p.IP) == ip && (p.QueuedAt.IsZero() || attemptAt.Sub(p.QueuedAt) <= maxPendingAge) {
			p.queueRecord.completed = true
			p.queueRecord.failed = false
		}
	}
}

func (w *autoBlockStateWork) finishCandidate(c *autoBlockCandidate) {
	w.queue.mu.Lock()
	c.finished = true
	w.queue.mu.Unlock()
}

func (w *autoBlockStateWork) rejectCandidate(c *autoBlockCandidate) {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(c.origins) == 0 && !c.completed && !c.lost {
		q.retries.candidateLoss.Lose(time.Now(), 1)
		c.lost = true
	}
	c.finished = true
}

func (w *autoBlockStateWork) requeueCandidate(p pendingIP) pendingIP {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	c := p.queueCandidate
	record := p.queueRecord
	if record == nil {
		record = &autoBlockPendingRecord{at: p.QueuedAt, lossKnown: true}
		q.retries.records = append(q.retries.records, record)
	}
	record.inFlight = true
	record.failed = c.failed || record.failed
	p.queueRecord = record
	c.queued = record
	return p
}

func (w *autoBlockStateWork) writeState(path string, state *blockState) error {
	q := w.queue
	q.mu.Lock()
	w.retryCycle.saving = true
	q.mu.Unlock()
	err := persistAutoBlockState(path, state)
	q.mu.Lock()
	q.retries.writeFailed = err != nil
	q.cleanup.writeFailed = err != nil
	if err != nil {
		w.failLocked()
		q.retries.depthKnown = false
		q.cleanup.depthKnown = false
	}
	q.mu.Unlock()
	// Rename may have succeeded before directory fsync returned an error.
	// Only readback can distinguish a retained old record from a new one.
	actual := state
	var readErr error
	if err != nil {
		w.progress()
		actual, readErr = readBlockState(path)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if readErr != nil {
		q.retries.readFailed = true
		q.retries.forgetUncertain()
		q.cleanup.readFailed = true
		w.forgetCleanupState()
	} else {
		q.retries.reconcile(actual.Pending, state.Pending, time.Now())
		w.observeCleanupState(actual, true)
		q.retries.readFailed = false
		q.cleanup.readFailed = false
		if err == nil {
			q.retries.historyUnknown = false
			q.cleanup.historyUnknown = false
		}
	}
	w.retryCycle.settled = true
	if w.cleanupCycle != nil && readErr == nil {
		w.cleanupCycle.settled = true
	}
	return err
}

func (w *autoBlockStateWork) saveState(path string, state *blockState) {
	if err := w.writeState(path, state); err != nil {
		logBlockStateFailure(path, err)
	}
}

func (w *autoBlockStateWork) finishRetriesLocked() {
	if w.readingState {
		w.queue.retries.readFailed = true
		w.queue.retries.forgetUncertain()
	}
	if w.retryCycle == nil {
		return
	}
	r := w.queue.retries
	if !w.completed {
		for c := range r.candidates {
			if c.running && !c.completed {
				for _, origin := range c.origins {
					origin.failed = true
				}
			}
		}
	}
	if !w.retryCycle.settled {
		switch {
		case w.retryCycle.saving:
			r.writeFailed = true
			r.forgetUncertain()
		case r.depthKnown:
			r.reconcile(r.disk, nil, time.Now())
		default:
			// The original state was unreadable, but no write started. Fresh work
			// accepted since that read cannot have reached the durable file.
			for c := range r.candidates {
				if !c.completed && !c.lost && len(c.origins) == 0 {
					r.candidateLoss.Lose(time.Now(), 1)
					c.lost = true
				}
			}
		}
	}
	clear(r.candidates)
}

func (r *autoBlockRetryQueue) statuses(now time.Time, active *autoBlockStateWork) (queuehealth.Status, queuehealth.Status) {
	pending := r.pendingLoss.Snapshot(now)
	pending.DroppedLowerBound = r.lowerBound
	pending.DepthUnavailable = !r.depthKnown
	pending.LagBasis = "queued_or_observed_age"
	if !r.depthKnown {
		pending.LagBasis = "unavailable"
	}
	candidates := r.candidateLoss.Snapshot(now)
	candidates.CapacityUnavailable = true
	candidates.DroppedLowerBound = r.lowerBound
	candidates.LagBasis = "operation_progress"
	processing := 0.0
	if active != nil {
		processing = max(0, now.Sub(active.at).Seconds())
	}
	failed := false
	for _, record := range r.records {
		if record.inFlight {
			pending.InFlight++
			pending.ProcessingSeconds = processing
		} else if r.depthKnown {
			pending.Depth++
			pending.LagSeconds = max(pending.LagSeconds, now.Sub(record.at).Seconds())
		}
		failed = failed || record.failed
	}
	for c := range r.candidates {
		if c.finished {
			continue
		}
		if c.running {
			candidates.InFlight++
			candidates.ProcessingSeconds = processing
		} else {
			candidates.Depth++
			candidates.LagSeconds = max(candidates.LagSeconds, now.Sub(c.at).Seconds())
		}
		failed = failed || c.failed
	}
	switch {
	case r.readFailed || r.writeFailed:
		pending.Status, pending.Reason = "degraded", "state_io"
	case failed:
		pending.Status, pending.Reason = "degraded", "retry_failed"
	case pending.InFlight > 0 && processing >= time.Minute.Seconds():
		pending.Status, pending.Reason = "degraded", "processing_lag"
	case pending.LagSeconds > maxPendingAge.Seconds():
		pending.Status, pending.Reason = "degraded", "backlog_lag"
	}
	if candidates.InFlight+candidates.Depth > 0 && processing >= time.Minute.Seconds() {
		candidates.Status, candidates.Reason = "degraded", "processing_lag"
	}
	return pending, candidates
}
