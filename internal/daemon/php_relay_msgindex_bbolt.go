package daemon

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

const msgIndexBucket = "phprelay:msgindex"

// All bbolt access goes through `*store.DB`'s phprelay helpers. The
// underlying `*bolt.DB` is unexported by design (internal/store/db.go);
// daemon code never imports go.etcd.io/bbolt directly.

// msgIndexPersister persists msgIDIndex entries to bbolt off the hot path.
// Public methods are safe for concurrent callers. Persistence failure does
// not affect the in-memory index; it only degrades restart-recovery and
// emits a Critical via the alerter callback.
//
// SetErrorCallback must be invoked BEFORE Start to establish a
// happens-before relationship between the writer of `onError` and the
// goroutine that reads it; concurrent callers after Start are not safe.
type msgIndexPersister struct {
	db         *store.DB
	queue      chan persistOp
	flushEvery time.Duration
	batchSize  int
	stopCh     chan struct{}
	doneCh     chan struct{}
	flushReqCh chan chan struct{}

	droppedTotal uint64
	errorsTotal  uint64

	onError func(alert.Finding)
	metrics *phpRelayMetrics
}

type persistOp struct {
	msgID string
	entry indexEntry
}

func newMsgIndexPersister(db *store.DB, queueSize int, flushEvery time.Duration) *msgIndexPersister {
	if queueSize <= 0 {
		queueSize = 4096
	}
	if flushEvery <= 0 {
		flushEvery = 100 * time.Millisecond
	}
	return &msgIndexPersister{
		db:         db,
		queue:      make(chan persistOp, queueSize),
		flushEvery: flushEvery,
		batchSize:  256,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		flushReqCh: make(chan chan struct{}),
		onError:    func(alert.Finding) {},
	}
}

// SetErrorCallback wires Critical findings emission for bbolt failures.
// Optional -- nil disables emission (used by tests). Must be called before
// Start; concurrent invocation after Start is not safe.
func (p *msgIndexPersister) SetErrorCallback(fn func(alert.Finding)) {
	if fn != nil {
		p.onError = fn
	}
}

// SetMetrics wires the phpRelayMetrics sink. Optional -- nil disables
// observation (used by tests). Must be called before Start; concurrent
// invocation after Start is not safe.
func (p *msgIndexPersister) SetMetrics(m *phpRelayMetrics) {
	p.metrics = m
}

func (p *msgIndexPersister) Start() {
	go p.run()
}

func (p *msgIndexPersister) Stop() {
	close(p.stopCh)
	<-p.doneCh
}

// Enqueue is non-blocking. Returns immediately; the op is dropped if the
// queue is full (in which case DroppedCount increments).
func (p *msgIndexPersister) Enqueue(msgID string, e indexEntry) {
	select {
	case p.queue <- persistOp{msgID: msgID, entry: e}:
	default:
		atomic.AddUint64(&p.droppedTotal, 1)
		if p.metrics != nil {
			p.metrics.MsgindexPersistDropped.Inc()
		}
	}
}

// Flush blocks until the persister has drained whatever was already
// enqueued at call time. For tests and shutdown.
func (p *msgIndexPersister) Flush() {
	done := make(chan struct{})
	select {
	case p.flushReqCh <- done:
		<-done
	case <-p.stopCh:
	}
}

func (p *msgIndexPersister) DroppedCount() uint64 {
	return atomic.LoadUint64(&p.droppedTotal)
}

func (p *msgIndexPersister) ErrorCount() uint64 {
	return atomic.LoadUint64(&p.errorsTotal)
}

// Lookup reads an entry from bbolt by msgID.
func (p *msgIndexPersister) Lookup(msgID string) (indexEntry, bool, error) {
	raw, ok, err := p.db.PHPRelayGet(msgIndexBucket, msgID)
	if err != nil || !ok {
		return indexEntry{}, false, err
	}
	var e indexEntry
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&e); err != nil {
		return indexEntry{}, false, fmt.Errorf("decode %s: %w", msgID, err)
	}
	return e, true, nil
}

// SweepBolt deletes phprelay:msgindex entries whose At <= cutoff.
// Returns the number of entries removed. Called by Flow E's 1-min ticker.
// Corrupt rows (decode failure) are also dropped to keep the bucket
// healthy.
func (p *msgIndexPersister) SweepBolt(cutoff time.Time) (int, error) {
	return p.db.PHPRelaySweep(msgIndexBucket, func(_, value []byte) bool {
		var e indexEntry
		if err := gob.NewDecoder(bytes.NewReader(value)).Decode(&e); err != nil {
			return true // drop corrupt rows
		}
		return !e.At.After(cutoff)
	})
}

func (p *msgIndexPersister) run() {
	defer close(p.doneCh)
	ticker := time.NewTicker(p.flushEvery)
	defer ticker.Stop()
	var pending []persistOp
	for {
		select {
		case <-p.stopCh:
			p.commitBatch(pending)
			return
		case op := <-p.queue:
			pending = append(pending, op)
			if len(pending) >= p.batchSize {
				p.commitBatch(pending)
				pending = pending[:0]
			}
		case <-ticker.C:
			if len(pending) > 0 {
				p.commitBatch(pending)
				pending = pending[:0]
			}
		case done := <-p.flushReqCh:
			// Drain queue before flushing.
			drain := true
			for drain {
				select {
				case op := <-p.queue:
					pending = append(pending, op)
				default:
					drain = false
				}
			}
			p.commitBatch(pending)
			pending = pending[:0]
			close(done)
		}
	}
}

func (p *msgIndexPersister) commitBatch(ops []persistOp) {
	if len(ops) == 0 {
		return
	}
	kvs := make([]store.PHPRelayKV, 0, len(ops))
	var buf bytes.Buffer
	for _, op := range ops {
		buf.Reset()
		if err := gob.NewEncoder(&buf).Encode(&op.entry); err != nil {
			// Encoding failure is a code bug, not a transient I/O issue.
			// Skip the offending op and continue with the rest of the batch.
			atomic.AddUint64(&p.errorsTotal, 1)
			if p.metrics != nil {
				p.metrics.MsgindexPersistErrors.Inc()
			}
			p.onError(alert.Finding{
				Severity: alert.Critical,
				Check:    "email_php_relay_msgindex_persist_failed",
				Message:  fmt.Sprintf("encode %s: %v", op.msgID, err),
			})
			continue
		}
		kvs = append(kvs, store.PHPRelayKV{
			Key:   []byte(op.msgID),
			Value: append([]byte(nil), buf.Bytes()...),
		})
	}
	if err := p.db.PHPRelayPutBatch(msgIndexBucket, kvs); err != nil {
		atomic.AddUint64(&p.errorsTotal, 1)
		if p.metrics != nil {
			p.metrics.MsgindexPersistErrors.Inc()
		}
		p.onError(alert.Finding{
			Severity: alert.Critical,
			Check:    "email_php_relay_msgindex_persist_failed",
			Message:  fmt.Sprintf("phprelay:msgindex commit failed (%d ops): %v", len(ops), err),
		})
	}
}
