package processctx

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func enricherQueueStatus(t *testing.T, e *Enricher) queuehealth.Status {
	t.Helper()
	provider, ok := any(e).(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	})
	if !ok {
		t.Fatal("process-context enrichment has no queue health")
	}
	got, exists := provider.QueueStatuses(time.Now())["enrichment"]
	if !exists {
		t.Fatal("process-context enrichment has no queue row")
	}
	return got
}

func TestEnricherQueueEvictsOldestAndRetainsWaitingAge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := newTestCache(8, 0)
		e := NewEnricher(cache, &fakeReader{}, EnricherConfig{Workers: 1, QueueCap: 2})
		for pid := 1; pid <= 3; pid++ {
			if !e.Enqueue(EnrichRequest{PID: pid}) {
				t.Fatalf("oldest eviction refused newer request %d", pid)
			}
			if pid < 3 {
				time.Sleep(10 * time.Second)
			}
		}
		got := enricherQueueStatus(t, e)
		if got.Depth != 2 || got.Capacity != 2 || got.InFlight != 0 || got.DroppedTotal != 1 || got.LagSeconds != 10 {
			t.Fatalf("oldest eviction changed remaining age or lost accounting: %+v", got)
		}
		e.Start()
		defer e.Stop()
		synctest.Wait()
		for pid := 1; pid <= 3; pid++ {
			if _, exists := cache.Get(pid); exists != (pid != 1) {
				t.Errorf("oldest eviction cached the wrong process %d: exists=%v", pid, exists)
			}
		}
		got = enricherQueueStatus(t, e)
		stats := e.Stats()
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 || stats.Enqueued != 3 || stats.Reads != 2 || stats.Drops != 1 {
			t.Fatalf("drain changed eviction accounting: queue=%+v stats=%+v", got, stats)
		}
	})
}

func TestEnricherQueueShutdownCountsBufferedRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := newTestCache(8, 0)
		release := make(chan struct{})
		releaseReader := sync.OnceFunc(func() { close(release) })
		defer releaseReader()
		var calls atomic.Int32
		reader := procReaderFunc(func(pid int) (processEntry, error) {
			calls.Add(1)
			<-release
			return processEntry{PID: pid, UID: 1001, UIDKnown: true, ProcRead: true}, nil
		})
		e := NewEnricher(cache, reader, EnricherConfig{Workers: 1, QueueCap: 3})
		e.Start()
		defer func() { releaseReader(); e.Stop() }()
		if !e.Enqueue(EnrichRequest{PID: 1}) {
			t.Fatal("running request refused")
		}
		synctest.Wait()
		for pid := 2; pid <= 4; pid++ {
			if !e.Enqueue(EnrichRequest{PID: pid}) {
				t.Fatalf("queued request refused: %d", pid)
			}
		}
		stopped := make(chan struct{})
		go func() { defer close(stopped); e.Stop() }()
		<-e.stopCh
		synctest.Wait()
		select {
		case <-stopped:
			t.Error("Stop returned while a reader owned a request")
		default:
		}
		releaseReader()
		<-stopped
		if calls.Load() != 1 || len(e.queue) != 0 || e.Stats().Drops != 3 {
			t.Fatalf("shutdown started abandoned work or concealed its loss: calls=%d queued=%d stats=%+v", calls.Load(), len(e.queue), e.Stats())
		}
		if cache.Len() != 1 {
			t.Fatalf("shutdown discarded the already-running successful read: cached=%d", cache.Len())
		}
		got := enricherQueueStatus(t, e)
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.Status != "degraded" {
			t.Fatalf("shutdown loss missing from queue health: %+v", got)
		}
	})
}

func TestEnricherQueueDistinguishesExpectedStalenessFromFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := newTestCache(8, 0)
		reader := procReaderFunc(func(pid int) (processEntry, error) {
			switch pid {
			case 1:
				return processEntry{}, ErrProcessGone
			case 2:
				return processEntry{}, errors.New("process read failed")
			case 3:
				return processEntry{PID: pid, UID: 1002, UIDKnown: true, ProcRead: true}, nil
			default:
				return processEntry{PID: pid, UID: 1001, UIDKnown: true, ProcRead: true}, nil
			}
		})
		e := NewEnricher(cache, reader, EnricherConfig{Workers: 1, QueueCap: 4})
		e.Start()
		defer e.Stop()
		for pid := 1; pid <= 4; pid++ {
			if !e.Enqueue(EnrichRequest{PID: pid, UID: 1001, UIDKnown: true}) {
				t.Fatalf("request %d refused", pid)
			}
		}
		synctest.Wait()
		stats := e.Stats()
		if stats.Reads != 4 || stats.Errors != 1 || stats.Stale != 1 || cache.Len() != 1 {
			t.Fatalf("process disappearance or stale identity was misclassified: stats=%+v cached=%d", stats, cache.Len())
		}
		if _, exists := cache.Get(4); !exists {
			t.Fatal("confirmed live process was not cached")
		}
		got := enricherQueueStatus(t, e)
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 1 || got.Status != "ok" {
			t.Fatalf("normal process churn inflated failure health: %+v", got)
		}
	})
}

type queueIdentityResolver func(int) (string, string)

func (f queueIdentityResolver) Resolve(uid int) (string, string) { return f(uid) }

func TestEnricherQueueTracksTheWholeProcessingPath(t *testing.T) {
	for _, phase := range []string{"reader", "observer", "resolver", "cache"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				releaseWork := sync.OnceFunc(func() { close(release) })
				defer releaseWork()
				block := func(at string) {
					if at == phase {
						<-release
					}
				}
				cache := newTestCache(8, 0)
				cache.now = func() time.Time { block("cache"); return time.Now() }
				reader := procReaderFunc(func(pid int) (processEntry, error) {
					block("reader")
					return processEntry{PID: pid, UID: 1001, UIDKnown: true, ProcRead: true}, nil
				})
				e := NewEnricher(cache, reader, EnricherConfig{
					Workers: 1, QueueCap: 2,
					Resolver: queueIdentityResolver(func(int) (string, string) {
						block("resolver")
						return "account-1", "account-1"
					}),
				})
				e.SetLatencyObserver(func(float64) { block("observer") })
				e.Start()
				defer func() { releaseWork(); e.Stop() }()
				if !e.Enqueue(EnrichRequest{PID: 1}) {
					t.Fatal("running request refused")
				}
				synctest.Wait()
				if !e.Enqueue(EnrichRequest{PID: 2}) {
					t.Fatal("waiting request refused")
				}
				time.Sleep(61 * time.Second)
				got := enricherQueueStatus(t, e)
				if got.Depth != 1 || got.InFlight != 1 || got.DroppedTotal != 0 || got.LagSeconds != 61 || got.ProcessingSeconds != 61 || got.Status != "degraded" {
					t.Fatalf("processing disappeared while %s held the request: %+v", phase, got)
				}
				releaseWork()
				synctest.Wait()
				got = enricherQueueStatus(t, e)
				if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" || cache.Len() != 2 || e.Stats().Reads != 2 {
					t.Fatalf("completed processing did not recover: queue=%+v cached=%d stats=%+v", got, cache.Len(), e.Stats())
				}
			})
		})
	}
}

func TestEnricherQueuePanicSettlesOnlyOwnedRequest(t *testing.T) {
	e := NewEnricher(newTestCache(8, 0), procReaderFunc(func(int) (processEntry, error) {
		panic("reader failed")
	}), EnricherConfig{Workers: 1, QueueCap: 3})
	for pid := 1; pid <= 3; pid++ {
		if !e.Enqueue(EnrichRequest{PID: pid}) {
			t.Fatalf("request %d refused", pid)
		}
	}
	e.wg.Add(1)
	var caught any
	func() { defer func() { caught = recover() }(); e.worker() }()
	if caught != "reader failed" {
		t.Fatalf("worker panic was concealed: %v", caught)
	}
	got := enricherQueueStatus(t, e)
	if got.Depth != 2 || got.InFlight != 0 || got.DroppedTotal != 1 || e.Stats().Reads != 1 {
		t.Fatalf("panic lost its request or damaged waiting work: queue=%+v stats=%+v", got, e.Stats())
	}
	e.Stop()
	got = enricherQueueStatus(t, e)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 {
		t.Fatalf("shutdown after worker failure lost or repeated accounting: %+v", got)
	}
}

func TestEnricherQueueConcurrentProducersAndStopConserveRequests(t *testing.T) {
	e := NewEnricher(newTestCache(8, 0), procReaderFunc(func(int) (processEntry, error) {
		return processEntry{}, errors.New("read failed")
	}), EnricherConfig{Workers: 2, QueueCap: 4})
	e.Start()
	start := make(chan struct{})
	var callers sync.WaitGroup
	const producers, requests = 4, 64
	for producer := range producers {
		callers.Go(func() {
			<-start
			for i := range requests {
				e.Enqueue(EnrichRequest{PID: 1 + producer*requests + i})
			}
		})
	}
	for range 3 {
		callers.Go(func() { <-start; e.Stop() })
	}
	close(start)
	callers.Wait()
	stats := e.Stats()
	if len(e.queue) != 0 || stats.Drops+stats.Errors != producers*requests {
		t.Fatalf("concurrent shutdown lost incomplete requests: queued=%d stats=%+v", len(e.queue), stats)
	}
	got := enricherQueueStatus(t, e)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != producers*requests {
		t.Fatalf("queue health did not retain all incomplete requests: %+v", got)
	}
}

func TestEnricherQueueStoppedPoolCannotRestartBufferedWork(t *testing.T) {
	e := NewEnricher(newTestCache(8, 0), &fakeReader{}, EnricherConfig{Workers: 4, QueueCap: 3})
	for pid := 1; pid <= 3; pid++ {
		if !e.Enqueue(EnrichRequest{PID: pid}) {
			t.Fatalf("request %d refused", pid)
		}
	}
	e.Stop()
	e.Start()
	e.wg.Wait()
	if stats := e.Stats(); stats.Reads != 0 || stats.Drops != 3 || len(e.queue) != 0 {
		t.Fatalf("Start revived discarded work after Stop: queued=%d stats=%+v", len(e.queue), stats)
	}
}
