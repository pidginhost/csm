package processctx

import (
	"errors"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

// procReader is the slice of ProcReader the Enricher needs. Allows fakes.
type procReader interface {
	Read(pid int) (processEntry, error)
}

// EnrichRequest is the immutable event snapshot queued off the ring-buffer
// path. UID/Comm/StartedAt are used to reject stale PID reuse before caching
// /proc data.
type EnrichRequest struct {
	PID       int
	UID       int
	UIDKnown  bool
	Comm      string
	StartedAt time.Time
}

type enrichWork struct {
	req    EnrichRequest
	ticket queuehealth.Ticket
}

// IdentityResolver maps a process UID to username/account metadata. It must be
// cache-only in the common path. The daemon implementation uses
// checks.LookupUser's cached /etc/passwd reader and simple local account
// inference; it must not call NSS, LDAP, whmapi1, network services, or any
// blocking account enumerator from the enricher worker.
//
// Implementations SHOULD return within ~1ms in the common case. If a future
// implementation needs a backing data source that can block, refresh it in a
// separate cache outside the worker and have Resolve return ("", "") on cache
// miss rather than stalling the enrichment queue.
type IdentityResolver interface {
	Resolve(uid int) (user, account string)
}

type noopResolver struct{}

func (noopResolver) Resolve(int) (string, string) { return "", "" }

// EnricherConfig sizes the worker pool and queue.
type EnricherConfig struct {
	Workers  int
	QueueCap int
	Resolver IdentityResolver
}

// EnricherStats is a snapshot of enricher counters.
type EnricherStats struct {
	Enqueued uint64
	Drops    uint64
	Reads    uint64
	Errors   uint64
	Stale    uint64
}

// Enricher consumes PIDs and populates Cache from ProcReader.Read off the
// hot path. Enqueue is nonblocking. On overflow it drops the oldest queued
// request and records that drop, so the producer keeps moving and the queue
// favors fresher process snapshots.
type Enricher struct {
	cache    *Cache
	reader   procReader
	resolver IdentityResolver
	cfg      EnricherConfig

	queue      chan enrichWork
	queueStats *queuehealth.Tracker
	admission  sync.Mutex
	wg         sync.WaitGroup
	stopCh     chan struct{}
	started    bool
	stopped    bool
	stopOnce   sync.Once

	enqueued atomic.Uint64
	drops    atomic.Uint64
	reads    atomic.Uint64
	errors   atomic.Uint64
	stale    atomic.Uint64

	latencyMu      sync.RWMutex
	observeLatency func(float64)
}

// NewEnricher prepares a pool; Start launches its workers.
func NewEnricher(cache *Cache, reader procReader, cfg EnricherConfig) *Enricher {
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.QueueCap <= 0 {
		cfg.QueueCap = 1024
	}
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = noopResolver{}
	}
	return &Enricher{
		cache:      cache,
		reader:     reader,
		resolver:   resolver,
		cfg:        cfg,
		queue:      make(chan enrichWork, cfg.QueueCap),
		queueStats: queuehealth.New(cfg.QueueCap, time.Minute),
		stopCh:     make(chan struct{}),
	}
}

// Start launches the worker goroutines. Idempotent.
func (e *Enricher) Start() {
	e.admission.Lock()
	defer e.admission.Unlock()
	if e.started || e.stopped {
		return
	}
	e.started = true
	e.wg.Add(e.cfg.Workers)
	for i := 0; i < e.cfg.Workers; i++ {
		go e.worker()
	}
}

// Stop signals workers and waits for them to exit. Safe to call multiple times.
//
// The pool cannot restart. Running reads finish; buffered requests are discarded
// and counted after workers relinquish ownership.
func (e *Enricher) Stop() {
	e.stopOnce.Do(func() {
		e.admission.Lock()
		e.stopped = true
		close(e.stopCh)
		close(e.queue)
		e.admission.Unlock()
		e.wg.Wait()
		for work := range e.queue {
			work.ticket.Reject(time.Now())
			e.drops.Add(1)
		}
	})
}

// Enqueue adds a request to the work queue. Returns false for an invalid PID
// or a stopped enricher. If the queue is full, the oldest pending request is
// dropped and the new one is queued.
func (e *Enricher) Enqueue(req EnrichRequest) bool {
	e.admission.Lock()
	defer e.admission.Unlock()
	if req.PID <= 0 || e.stopped {
		e.queueStats.Lose(time.Now(), 1)
		e.drops.Add(1)
		return false
	}
	work := enrichWork{req: req, ticket: e.queueStats.Begin(time.Now())}
	select {
	case e.queue <- work:
	default:
		select {
		case oldest := <-e.queue:
			oldest.ticket.Reject(time.Now())
			e.drops.Add(1)
		default:
		}
		// Other producers and close are excluded; consumers can only free slots.
		e.queue <- work
	}
	e.enqueued.Add(1)
	return true
}

func (e *Enricher) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	out := map[string]queuehealth.Status{"enrichment": e.queueStats.Snapshot(now)}
	if reader, ok := e.reader.(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	}); ok {
		maps.Copy(out, reader.QueueStatuses(now))
	}
	return out
}

// SetLatencyObserver installs an optional callback used by metrics.
func (e *Enricher) SetLatencyObserver(fn func(float64)) {
	e.latencyMu.Lock()
	defer e.latencyMu.Unlock()
	e.observeLatency = fn
}

func (e *Enricher) observe(seconds float64) {
	e.latencyMu.RLock()
	fn := e.observeLatency
	e.latencyMu.RUnlock()
	if fn != nil {
		fn(seconds)
	}
}

func (e *Enricher) shouldCache(req EnrichRequest, entry processEntry) bool {
	reqUIDKnown := req.UIDKnown || req.UID != 0
	if reqUIDKnown {
		if !entry.UIDKnown || req.UID != entry.UID {
			return false
		}
	} else if !entry.UIDKnown {
		return false
	}
	if req.Comm != "" && entry.Comm != req.Comm {
		return false
	}
	// PID-reuse guard: when the detector supplied a process-start
	// snapshot, the /proc-derived start time must be present and match
	// within a small tolerance. A missing or mismatched /proc value means
	// the enricher cannot prove it is looking at the same process.
	if !processStartMatches(req.StartedAt, entry.StartedAt) {
		return false
	}
	return true
}

// processStartTimeTolerance bounds the allowed clock skew between a
// detector's process-start snapshot and /proc/<pid>/stat's starttime. Five
// seconds covers clock granularity and slow pickup without letting a PID-reuse
// race slip past.
const processStartTimeTolerance = 5 * time.Second

func processStartMatches(want, got time.Time) bool {
	if want.IsZero() {
		return true
	}
	if got.IsZero() {
		return false
	}
	diff := want.Sub(got)
	if diff < 0 {
		diff = -diff
	}
	return diff <= processStartTimeTolerance
}

func (e *Enricher) enrichIdentity(entry *processEntry) {
	if !entry.UIDKnown {
		return
	}
	user, account := e.resolver.Resolve(entry.UID)
	entry.User = user
	entry.Account = account
}

// Stats returns a counter snapshot.
func (e *Enricher) Stats() EnricherStats {
	return EnricherStats{
		Enqueued: e.enqueued.Load(),
		Drops:    e.drops.Load(),
		Reads:    e.reads.Load(),
		Errors:   e.errors.Load(),
		Stale:    e.stale.Load(),
	}
}

func (e *Enricher) worker() {
	defer e.wg.Done()
	for {
		select {
		case <-e.stopCh:
			return
		default:
		}
		select {
		case <-e.stopCh:
			return
		case work, ok := <-e.queue:
			if !ok {
				return
			}
			e.process(work)
		}
	}
}

func (e *Enricher) process(work enrichWork) {
	start := time.Now()
	work.ticket.Start(start)
	completed := false
	defer func() {
		if completed {
			work.ticket.Finish(time.Now())
		} else {
			work.ticket.Reject(time.Now())
		}
	}()
	e.reads.Add(1)
	entry, err := e.reader.Read(work.req.PID)
	e.observe(time.Since(start).Seconds())
	if err != nil {
		if errors.Is(err, ErrProcessGone) {
			completed = true
		} else {
			e.errors.Add(1)
		}
		return
	}
	if !e.shouldCache(work.req, entry) {
		e.stale.Add(1)
		completed = true
		return
	}
	e.enrichIdentity(&entry)
	e.cache.Put(entry)
	completed = true
}
