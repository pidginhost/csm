package daemon

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	csmlog "github.com/pidginhost/csm/internal/log"
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

type verdictJob struct {
	key      string
	ip       string
	reason   string
	severity string
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
	ask      verdictAskFunc
	ttl      time.Duration
	jobs     chan verdictJob
	wg       sync.WaitGroup
	mu       sync.Mutex
	cache    map[string]verdictEntry
	inFlight map[string]bool
	dropped  atomic.Int64
}

func newVerdictEnricher(opts verdictEnricherOpts) *verdictEnricher {
	if opts.Workers <= 0 {
		opts.Workers = 2
	}
	if opts.Queue <= 0 {
		opts.Queue = 64
	}
	if opts.TTL <= 0 {
		opts.TTL = time.Minute
	}
	return &verdictEnricher{
		ask:      opts.Ask,
		ttl:      opts.TTL,
		jobs:     make(chan verdictJob, opts.Queue),
		cache:    make(map[string]verdictEntry),
		inFlight: make(map[string]bool),
	}
}

func (e *verdictEnricher) start(ctx context.Context) {
	workers := cap(e.jobs)
	if workers > 4 {
		workers = 4
	}
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.work(ctx)
		}()
	}
}

func (e *verdictEnricher) wait() { e.wg.Wait() }

func (e *verdictEnricher) droppedEnrichments() int64 { return e.dropped.Load() }

// annotate applies a cached verdict to f and reports whether it could. On a
// miss it queues the lookup and returns immediately: the caller dispatches the
// finding now and later events for the same destination carry the answer.
func (e *verdictEnricher) annotate(f *alert.Finding, ip, reason, severity string) bool {
	if e == nil || f == nil || e.ask == nil {
		return false
	}
	key := ip + "\x00" + reason

	e.mu.Lock()
	entry, ok := e.cache[key]
	fresh := ok && time.Since(entry.at) < e.ttl
	queued := e.inFlight[key]
	if !fresh && !queued {
		e.inFlight[key] = true
	}
	e.mu.Unlock()

	if fresh {
		applyVerdictEntry(f, entry)
		return true
	}
	if queued {
		return false
	}
	select {
	case e.jobs <- verdictJob{key: key, ip: ip, reason: reason, severity: severity}:
	default:
		// Saturated: the annotation is what we give up, never the finding.
		e.mu.Lock()
		delete(e.inFlight, key)
		e.mu.Unlock()
		e.dropped.Add(1)
	}
	return false
}

func (e *verdictEnricher) work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-e.jobs:
			if !ok {
				return
			}
			resp, err := e.ask(ctx, verdict.Request{
				IP:       job.ip,
				Reason:   job.reason,
				Severity: job.severity,
				Source:   "bpf_enforcement",
			})
			e.mu.Lock()
			delete(e.inFlight, job.key)
			if err == nil {
				// A failure is not an answer: leaving it uncached lets the next
				// event retry instead of inheriting a permanent blank.
				e.cache[job.key] = verdictEntry{
					tenantID: resp.TenantID,
					verdict:  resp.Verdict,
					note:     resp.Note,
					at:       time.Now(),
				}
			}
			e.mu.Unlock()
			if err != nil {
				csmlog.Warn("bpf enforcement verdict callback failed", "err", err, "dst", job.ip)
			}
		}
	}
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
