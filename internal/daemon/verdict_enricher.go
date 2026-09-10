package daemon

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/verdict"
)

// verdictAskFunc asks the operator's callback about one destination.
type verdictAskFunc func(ctx context.Context, req verdict.Request) (verdict.Response, error)

type verdictEnricherOpts struct {
	Ask     verdictAskFunc
	Workers int
	Queue   int
	TTL     time.Duration
}

type verdictEntry struct {
	tenantID string
	verdict  string
	note     string
	at       time.Time
}

type verdictKey struct {
	ip       string
	reason   string
	severity string
}

type verdictJob struct {
	key    verdictKey
	ticket queuehealth.Ticket
}

// verdictEnricher annotates findings with the operator's verdict without ever
// standing between the BPF ring buffer and the alert channel.
//
// The callback used to run inline in the consumer loop: one denied connection
// could hold the reader for the callback's whole timeout while a 256-slot ring
// overflowed, so an optional annotation cost real security events. Enrichment
// now happens on a bounded worker pool behind a short-lived cache. A finding is
// dispatched immediately either way; what a cache miss loses is the annotation
// on that first event, not the event.
type verdictEnricher struct {
	ask        verdictAskFunc
	ttl        time.Duration
	jobs       chan verdictJob
	workers    int
	cacheCap   int
	wg         sync.WaitGroup
	mu         sync.Mutex
	cache      map[verdictKey]verdictEntry
	inFlight   map[verdictKey]bool
	dropped    atomic.Int64
	queueStats *queuehealth.Tracker
	ctx        context.Context
	stopped    bool
	stopOnce   sync.Once
}

func newVerdictEnricher(opts verdictEnricherOpts) *verdictEnricher {
	if opts.Workers <= 0 {
		opts.Workers = 2
	}
	if opts.Workers > 4 {
		opts.Workers = 4
	}
	if opts.Queue <= 0 {
		opts.Queue = 64
	}
	if opts.TTL <= 0 {
		opts.TTL = time.Minute
	}
	return &verdictEnricher{
		ask:        opts.Ask,
		ttl:        opts.TTL,
		jobs:       make(chan verdictJob, opts.Queue),
		workers:    opts.Workers,
		cacheCap:   opts.Queue,
		cache:      make(map[verdictKey]verdictEntry),
		inFlight:   make(map[verdictKey]bool),
		queueStats: queuehealth.New(opts.Queue, time.Minute),
	}
}

func (e *verdictEnricher) start(ctx context.Context) {
	e.mu.Lock()
	e.ctx = ctx
	e.mu.Unlock()
	for i := 0; i < e.workers; i++ {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.work(ctx)
		}()
	}
}

func (e *verdictEnricher) wait() {
	e.stopOnce.Do(func() {
		e.mu.Lock()
		e.stopped = true
		close(e.jobs)
		e.mu.Unlock()
		e.wg.Wait()
		e.mu.Lock()
		defer e.mu.Unlock()
		for job := range e.jobs {
			delete(e.inFlight, job.key)
			job.ticket.Reject(time.Now())
			e.dropped.Add(1)
		}
	})
}

func (e *verdictEnricher) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{"verdict": e.queueStats.Snapshot(now)}
}

func (e *verdictEnricher) droppedEnrichments() int64 { return e.dropped.Load() }

// annotate applies a cached verdict to f and reports whether it could. On a
// miss it queues the lookup and returns immediately: the caller dispatches the
// finding now and later events for the same destination carry the answer.
func (e *verdictEnricher) annotate(f *alert.Finding, ip, reason, severity string) bool {
	if e == nil || f == nil || e.ask == nil {
		return false
	}
	key := verdictKey{ip: ip, reason: reason, severity: severity}

	e.mu.Lock()
	entry, ok := e.cache[key]
	fresh := ok && time.Since(entry.at) < e.ttl
	if ok && !fresh {
		delete(e.cache, key)
	}
	if fresh {
		e.mu.Unlock()
		applyVerdictEntry(f, entry)
		return true
	}
	defer e.mu.Unlock()
	if e.stopped || (e.ctx != nil && e.ctx.Err() != nil) {
		e.queueStats.Lose(time.Now(), 1)
		e.dropped.Add(1)
		return false
	}
	if e.inFlight[key] {
		return false
	}
	ticket := e.queueStats.Begin(time.Now())
	e.inFlight[key] = true
	select {
	case e.jobs <- verdictJob{key: key, ticket: ticket}:
	default:
		// Saturated: the annotation is what we give up, never the finding.
		delete(e.inFlight, key)
		ticket.Reject(time.Now())
		e.dropped.Add(1)
	}
	return false
}

func (e *verdictEnricher) work(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case job, ok := <-e.jobs:
			if !ok {
				return
			}
			if err := e.processJob(ctx, job); err != nil {
				csmlog.Warn("bpf enforcement verdict callback failed", "err", err, "dst", job.key.ip)
			}
		}
	}
}

func (e *verdictEnricher) processJob(ctx context.Context, job verdictJob) error {
	job.ticket.Start(time.Now())
	completed := false
	defer func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		delete(e.inFlight, job.key)
		if completed {
			job.ticket.Finish(time.Now())
		} else {
			job.ticket.Reject(time.Now())
			e.dropped.Add(1)
		}
	}()
	resp, err := e.ask(ctx, verdict.Request{
		IP:       job.key.ip,
		Reason:   job.key.reason,
		Severity: job.key.severity,
		Source:   "bpf_enforcement",
	})
	if err != nil {
		// A failure is not an answer: the next event must be able to retry.
		return err
	}
	e.mu.Lock()
	now := time.Now()
	e.pruneCacheLocked(now)
	e.cache[job.key] = verdictEntry{
		tenantID: resp.TenantID,
		verdict:  resp.Verdict,
		note:     resp.Note,
		at:       now,
	}
	e.mu.Unlock()
	completed = true
	return nil
}

func (e *verdictEnricher) pruneCacheLocked(now time.Time) {
	for key, entry := range e.cache {
		if now.Sub(entry.at) >= e.ttl {
			delete(e.cache, key)
		}
	}
	if len(e.cache) < e.cacheCap {
		return
	}
	var oldestKey verdictKey
	var oldestAt time.Time
	for key, entry := range e.cache {
		if oldestAt.IsZero() || entry.at.Before(oldestAt) {
			oldestKey = key
			oldestAt = entry.at
		}
	}
	delete(e.cache, oldestKey)
}

func applyVerdictEntry(f *alert.Finding, entry verdictEntry) {
	if entry.tenantID != "" && f.TenantID == "" {
		f.TenantID = entry.tenantID
	}
	if entry.verdict != "" {
		appendFindingDetail(f, "Verdict callback: "+entry.verdict)
	}
	if entry.tenantID != "" {
		appendFindingDetail(f, "Verdict tenant: "+entry.tenantID)
	}
	if entry.note != "" {
		appendFindingDetail(f, "Verdict note: "+entry.note)
	}
}
