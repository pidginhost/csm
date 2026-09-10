package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/verdict"
)

func verdictQueueStatus(t *testing.T, e *verdictEnricher) queuehealth.Status {
	t.Helper()
	provider, ok := any(e).(queueSource)
	if !ok {
		t.Fatal("verdict annotation queue has no health provider")
	}
	got, exists := provider.QueueStatuses(time.Now())["verdict"]
	if !exists {
		t.Fatal("verdict annotation queue has no health row")
	}
	return got
}

func queueVerdict(e *verdictEnricher, id int) alert.Finding {
	f := alert.Finding{Check: "bpf_egress"}
	e.annotate(&f, fmt.Sprintf("192.0.2.%d", id), "egress", "Critical")
	return f
}

func TestVerdictQueueRefusesWorkAfterShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := newVerdictEnricher(verdictEnricherOpts{
		Ask: func(context.Context, verdict.Request) (verdict.Response, error) {
			t.Error("stopped enricher called the verdict service")
			return verdict.Response{}, nil
		},
		Workers: 1,
		Queue:   2,
	})
	e.start(ctx)
	e.wait()
	f := queueVerdict(e, 1)
	if len(e.jobs) != 0 || len(e.inFlight) != 0 || e.droppedEnrichments() != 1 {
		t.Fatalf("stopped enricher accepted unreachable work: queued=%d retained=%d dropped=%d", len(e.jobs), len(e.inFlight), e.droppedEnrichments())
	}
	if f.Check != "bpf_egress" || f.TenantID != "" {
		t.Fatalf("refused annotation changed the finding: %+v", f)
	}
}

func TestVerdictQueueRetainsWaitingAndRunningAnnotations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		release := make(chan struct{})
		releaseCallbacks := sync.OnceFunc(func() { close(release) })
		defer releaseCallbacks()
		var calls atomic.Int32
		e := newVerdictEnricher(verdictEnricherOpts{
			Ask: func(context.Context, verdict.Request) (verdict.Response, error) {
				calls.Add(1)
				<-release
				return verdict.Response{TenantID: "account-1"}, nil
			},
			Workers: 2,
			Queue:   3,
		})
		e.start(ctx)
		defer func() { releaseCallbacks(); cancel(); e.wait() }()
		queueVerdict(e, 1)
		queueVerdict(e, 2)
		synctest.Wait()
		for i := 3; i <= 8; i++ {
			f := queueVerdict(e, i)
			if f.Check != "bpf_egress" || f.TenantID != "" {
				t.Fatalf("queued annotation changed immediate finding delivery: %+v", f)
			}
		}
		for range 10 {
			queueVerdict(e, 1)
			queueVerdict(e, 3)
		}
		time.Sleep(61 * time.Second)
		got := verdictQueueStatus(t, e)
		if got.Depth != 3 || got.Capacity != 3 || got.InFlight != 2 || got.DroppedTotal != 3 || got.LagSeconds != 61 || got.ProcessingSeconds != 61 || got.Status != "degraded" {
			t.Fatalf("coalescing concealed annotation queue pressure: %+v", got)
		}
		releaseCallbacks()
		synctest.Wait()
		got = verdictQueueStatus(t, e)
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.Status != "ok" || calls.Load() != 5 {
			t.Fatalf("completed callbacks did not recover after loss aged out: status=%+v calls=%d", got, calls.Load())
		}
	})
}

func TestVerdictQueueCallbackFailuresRemainVisibleAfterRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		fail, calls := true, 0
		e := newVerdictEnricher(verdictEnricherOpts{
			Ask: func(context.Context, verdict.Request) (verdict.Response, error) {
				calls++
				if fail {
					return verdict.Response{}, errors.New("verdict service unavailable")
				}
				return verdict.Response{TenantID: "account-1"}, nil
			},
			Workers: 1,
			Queue:   4,
		})
		e.start(ctx)
		defer func() { cancel(); e.wait() }()
		for range 3 {
			queueVerdict(e, 1)
			synctest.Wait()
		}
		got := verdictQueueStatus(t, e)
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.Status != "degraded" || calls != 3 {
			t.Fatalf("callback failures vanished or were cached: status=%+v calls=%d", got, calls)
		}
		fail = false
		queueVerdict(e, 1)
		synctest.Wait()
		f := queueVerdict(e, 1)
		if f.TenantID != "account-1" || calls != 4 {
			t.Fatalf("successful retry did not populate the cache: finding=%+v calls=%d", f, calls)
		}
		got = verdictQueueStatus(t, e)
		if got.DroppedTotal != 3 || got.Depth != 0 || got.InFlight != 0 {
			t.Fatalf("successful retry changed earlier loss evidence: %+v", got)
		}
	})
}

func TestVerdictQueueShutdownAccountsForRunningAndWaitingWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		release := make(chan struct{})
		releaseCallbacks := sync.OnceFunc(func() { close(release) })
		defer releaseCallbacks()
		var calls atomic.Int32
		e := newVerdictEnricher(verdictEnricherOpts{
			Ask: func(ctx context.Context, _ verdict.Request) (verdict.Response, error) {
				calls.Add(1)
				<-release
				return verdict.Response{}, ctx.Err()
			},
			Workers: 2,
			Queue:   3,
		})
		e.start(ctx)
		queueVerdict(e, 1)
		queueVerdict(e, 2)
		synctest.Wait()
		for i := 3; i <= 5; i++ {
			queueVerdict(e, i)
		}
		cancel()
		stopped := make(chan struct{})
		go func() { defer close(stopped); e.wait() }()
		synctest.Wait()
		select {
		case <-stopped:
			t.Error("shutdown returned while callbacks still owned work")
		default:
		}
		releaseCallbacks()
		<-stopped
		if calls.Load() != 2 || len(e.jobs) != 0 || len(e.inFlight) != 0 {
			t.Fatalf("shutdown started queued callbacks or retained abandoned work: calls=%d queued=%d retained=%d", calls.Load(), len(e.jobs), len(e.inFlight))
		}
		got := verdictQueueStatus(t, e)
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 5 || got.Status != "degraded" {
			t.Fatalf("canceled and abandoned annotations disappeared: %+v", got)
		}
		e.wait()
		if got = verdictQueueStatus(t, e); got.DroppedTotal != 5 {
			t.Fatalf("repeated shutdown counted losses twice: %+v", got)
		}
	})
}

func TestVerdictQueuePanicReleasesTheRunningKey(t *testing.T) {
	e := newVerdictEnricher(verdictEnricherOpts{
		Ask: func(context.Context, verdict.Request) (verdict.Response, error) {
			panic("callback failure")
		},
		Queue: 3,
	})
	for i := 1; i <= 3; i++ {
		queueVerdict(e, i)
	}
	var caught any
	func() { defer func() { caught = recover() }(); e.work(context.Background()) }()
	if caught != "callback failure" {
		t.Fatalf("callback panic was concealed: %v", caught)
	}
	if len(e.inFlight) != 2 || len(e.jobs) != 2 {
		t.Fatalf("failed callback retained a key that can never finish: retained=%d queued=%d", len(e.inFlight), len(e.jobs))
	}
	for i := 1; i <= 3; i++ {
		key := verdictKey{ip: fmt.Sprintf("192.0.2.%d", i), reason: "egress", severity: "Critical"}
		if e.inFlight[key] != (i != 1) {
			t.Errorf("callback panic retained or removed the wrong pending key: %v", key)
		}
	}
	got := verdictQueueStatus(t, e)
	if got.Depth != 2 || got.InFlight != 0 || got.DroppedTotal != 1 {
		t.Fatalf("panic damaged unrelated work or lost accounting: %+v", got)
	}
}

func TestVerdictQueueConcurrentAdmissionAndShutdown(t *testing.T) {
	e := newVerdictEnricher(verdictEnricherOpts{
		Ask: func(context.Context, verdict.Request) (verdict.Response, error) {
			return verdict.Response{}, errors.New("callback failed")
		},
		Workers: 2,
		Queue:   4,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.start(ctx)
	start := make(chan struct{})
	var callers sync.WaitGroup
	const producers, requests = 4, 16
	for producer := range producers {
		callers.Go(func() {
			<-start
			for i := range requests {
				queueVerdict(e, 1+producer*requests+i)
			}
		})
	}
	for range 3 {
		callers.Go(func() { <-start; cancel(); e.wait() })
	}
	close(start)
	callers.Wait()
	got := verdictQueueStatus(t, e)
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != producers*requests || len(e.inFlight) != 0 {
		t.Fatalf("concurrent shutdown failed to account for every incomplete annotation: status=%+v retained=%d", got, len(e.inFlight))
	}
}
