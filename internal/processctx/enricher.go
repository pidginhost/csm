package processctx

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// procReader is the slice of ProcReader the Enricher needs. Allows fakes.
type procReader interface {
	Read(pid int) (processEntry, error)
}

// EnrichRequest is the immutable event snapshot queued off the ring-buffer
// path. UID/Comm are used to reject stale PID reuse before caching /proc data.
type EnrichRequest struct {
	PID       int
	UID       int
	UIDKnown  bool
	Comm      string
	StartedAt time.Time
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

	queue    chan EnrichRequest
	wg       sync.WaitGroup
	stopCh   chan struct{}
	started  atomic.Bool
	stopped  atomic.Bool
	stopOnce sync.Once

	enqueued atomic.Uint64
	drops    atomic.Uint64
	reads    atomic.Uint64
	errors   atomic.Uint64
	stale    atomic.Uint64

	latencyMu      sync.RWMutex
	observeLatency func(float64)
}

// NewEnricher returns a stopped Enricher. Call Start to launch workers.
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
		cache:    cache,
		reader:   reader,
		resolver: resolver,
		cfg:      cfg,
		queue:    make(chan EnrichRequest, cfg.QueueCap),
		stopCh:   make(chan struct{}),
	}
}

// Start launches the worker goroutines. Idempotent.
func (e *Enricher) Start() {
	if e.started.Swap(true) {
		return
	}
	for i := 0; i < e.cfg.Workers; i++ {
		e.wg.Add(1)
		go e.worker()
	}
}

// Stop signals workers and waits for them to exit. Safe to call multiple times.
//
// Queued requests are not drained: any EnrichRequest still in the channel
// when stopCh closes is dropped on the floor. Stats.Enqueued therefore stays
// ahead of Stats.Reads + Stats.Errors after shutdown by the queue depth.
// Acceptable on daemon shutdown because no caller is waiting for completion;
// operators reading the metrics post-restart should expect this delta.
func (e *Enricher) Stop() {
	e.stopOnce.Do(func() {
		e.stopped.Store(true)
		close(e.stopCh)
		e.wg.Wait()
	})
}

// Enqueue adds a request to the work queue. Returns false only when the
// enricher is stopped. If the queue is full, the oldest pending request is
// dropped and the new one is queued.
func (e *Enricher) Enqueue(req EnrichRequest) bool {
	if req.PID <= 0 || e.stopped.Load() {
		e.drops.Add(1)
		return false
	}
	select {
	case e.queue <- req:
		e.enqueued.Add(1)
		return true
	case <-e.stopCh:
		e.drops.Add(1)
		return false
	default:
		select {
		case <-e.queue:
			e.drops.Add(1)
		default:
		}
		select {
		case e.queue <- req:
			e.enqueued.Add(1)
			return true
		case <-e.stopCh:
			e.drops.Add(1)
			return false
		default:
			e.drops.Add(1)
			return false
		}
	}
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
	return true
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
		case req := <-e.queue:
			start := time.Now()
			e.reads.Add(1)
			entry, err := e.reader.Read(req.PID)
			e.observe(time.Since(start).Seconds())
			if err != nil {
				if errors.Is(err, ErrProcessGone) {
					continue
				}
				e.errors.Add(1)
				continue
			}
			if !e.shouldCache(req, entry) {
				e.stale.Add(1)
				continue
			}
			if !req.StartedAt.IsZero() {
				entry.StartedAt = req.StartedAt
			}
			e.enrichIdentity(&entry)
			e.cache.Put(entry)
		}
	}
}
