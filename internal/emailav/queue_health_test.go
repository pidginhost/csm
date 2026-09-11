package emailav

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	emime "github.com/pidginhost/csm/internal/mime"
	"github.com/pidginhost/csm/internal/queuehealth"
)

type controlledScanner struct {
	name string
	scan func() (Verdict, error)
}

func (s controlledScanner) Name() string                 { return s.name }
func (s controlledScanner) Available() bool              { return true }
func (s controlledScanner) Scan(string) (Verdict, error) { return s.scan() }

func emailQueue(t *testing.T, o *Orchestrator) queuehealth.Status {
	t.Helper()
	source, ok := any(o).(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	})
	if !ok {
		t.Fatal("email engine work has no health source")
	}
	rows := source.QueueStatuses(time.Now())
	s, ok := rows["scans"]
	if !ok || len(rows) != 1 {
		t.Fatalf("missing or unexpected email queue rows: %+v", rows)
	}
	return s
}

func TestEmailQueuePublication(t *testing.T) {
	o := NewOrchestrator(nil, time.Minute)
	s := emailQueue(t, o)
	if s.Status != "ok" || !s.CapacityUnavailable || s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 {
		t.Fatalf("idle queue: %+v", s)
	}
}

func TestEmailQueueRetainsTimedOutEngines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first, second := make(chan struct{}), make(chan struct{})
		o := NewOrchestrator([]Scanner{
			controlledScanner{"first", func() (Verdict, error) { <-first; return Verdict{}, errors.New("late failure") }},
			controlledScanner{"second", func() (Verdict, error) { <-second; return Verdict{Infected: true}, nil }},
		}, 30*time.Second)
		results := make(chan *ScanResult, 1)
		go func() { results <- o.ScanParts("controlled", []emime.ExtractedPart{{Filename: "part"}}, false) }()
		synctest.Wait()
		time.Sleep(29 * time.Second)
		if s := emailQueue(t, o); s.InFlight != 2 || s.Depth != 0 || s.Status != "ok" || s.DroppedTotal != 0 {
			t.Fatalf("engines within budget: %+v", s)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		got := <-results
		slices.Sort(got.TimedOutEngines)
		if got.Infected || len(got.Findings) != 0 || len(got.ErroredEngines) != 0 || !slices.Equal(got.TimedOutEngines, []string{"first", "second"}) {
			t.Fatalf("timeout changed fail-open result: %+v", got)
		}
		if s := emailQueue(t, o); s.Depth != 0 || s.InFlight != 2 || s.Reason != "processing_lag" || s.DroppedTotal != 2 {
			t.Fatalf("timeouts hid running engines: %+v", s)
		}
		time.Sleep(time.Minute)
		if s := emailQueue(t, o); s.InFlight != 2 || s.RecentDrops != 0 || s.Reason != "processing_lag" {
			t.Fatalf("aging losses hid running engines: %+v", s)
		}
		close(first)
		synctest.Wait()
		if s := emailQueue(t, o); s.InFlight != 1 || s.DroppedTotal != 2 {
			t.Fatalf("late error was counted twice or released a peer: %+v", s)
		}
		close(second)
		synctest.Wait()
		if s := emailQueue(t, o); s.Depth != 0 || s.InFlight != 0 || s.Status != "ok" || s.DroppedTotal != 2 {
			t.Fatalf("engine completion did not recover: %+v", s)
		}
	})
}

func TestEmailQueueErrorsAndRecoveredExits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o := NewOrchestrator([]Scanner{
			controlledScanner{"error", func() (Verdict, error) { return Verdict{}, errors.New("scan failure") }},
			controlledScanner{"panic", func() (Verdict, error) { panic("controlled scanner failure") }},
			controlledScanner{"exit", func() (Verdict, error) { runtime.Goexit(); return Verdict{}, nil }},
		}, 10*time.Second)
		result := o.ScanParts("controlled", []emime.ExtractedPart{{Filename: "part"}}, false)
		synctest.Wait()
		slices.Sort(result.TimedOutEngines)
		if result.Infected || len(result.Findings) != 0 || !slices.Equal(result.ErroredEngines, []string{"error"}) || !slices.Equal(result.TimedOutEngines, []string{"exit", "panic"}) {
			t.Fatalf("failure classification changed: %+v", result)
		}
		if s := emailQueue(t, o); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 3 || s.Reason != "dropped_work" {
			t.Fatalf("each failed scan must count once: %+v", s)
		}
		time.Sleep(time.Minute)
		if s := emailQueue(t, o); s.Status != "ok" || s.DroppedTotal != 3 || s.RecentDrops != 0 {
			t.Fatalf("failed scans did not recover: %+v", s)
		}
	})
}

func TestEmailQueueConcurrentCallsAndUnavailableEngines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		o := NewOrchestrator([]Scanner{
			controlledScanner{"active", func() (Verdict, error) { <-release; return Verdict{Infected: true, Signature: "controlled"}, nil }},
			&mockScanner{name: "unavailable"},
		}, time.Hour)
		results := make(chan *ScanResult, 3)
		for range 3 {
			go func() { results <- o.ScanParts("controlled", []emime.ExtractedPart{{Filename: "part"}}, false) }()
		}
		synctest.Wait()
		time.Sleep(31 * time.Second)
		if s := emailQueue(t, o); s.InFlight != 3 || s.Depth != 0 || !s.CapacityUnavailable || s.Status != "ok" || s.DroppedTotal != 0 {
			t.Fatalf("concurrent calls invented saturation or lost ownership: %+v", s)
		}
		close(release)
		for range 3 {
			got := <-results
			if !got.Infected || len(got.Findings) != 1 || got.Findings[0].Signature != "controlled" || !slices.Equal(got.FailedEngines, []string{"unavailable"}) || len(got.TimedOutEngines) != 0 || len(got.ErroredEngines) != 0 {
				t.Fatalf("completed scan result: %+v", got)
			}
		}
		synctest.Wait()
		if s := emailQueue(t, o); s.InFlight != 0 || s.Depth != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
			t.Fatalf("clean results or unavailable engines counted as loss: %+v", s)
		}
	})
}

func TestEmailQueueBufferedResultsAndConsumerStall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o := NewOrchestrator(nil, time.Hour)
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		results := make(chan engineScanResult, 2)
		var wg sync.WaitGroup
		for range 2 {
			o.startScan(ctx, &mockScanner{name: "clean", available: true}, "part", results, &wg)
		}
		wg.Wait()
		synctest.Wait()
		if s := emailQueue(t, o); s.Depth != 2 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
			t.Fatalf("buffered results lost ownership: %+v", s)
		}
		time.Sleep(61 * time.Second)
		if s := emailQueue(t, o); s.Depth != 2 || s.Reason != "backlog_lag" || s.LagSeconds != 61 {
			t.Fatalf("consumer stall inherited engine budget: %+v", s)
		}
		first, second := <-results, <-results
		first.work.received()
		second.work.received()
		first.work.finishDelivery(true)
		time.Sleep(61 * time.Second)
		if s := emailQueue(t, o); s.Depth != 0 || s.InFlight != 1 || s.Reason != "processing_lag" || s.ProcessingSeconds != 61 {
			t.Fatalf("result processing lost ownership: %+v", s)
		}
		second.work.finishDelivery(true)
		if s := emailQueue(t, o); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
			t.Fatalf("result drain did not recover: %+v", s)
		}
	})
}

type heldDoneContext struct {
	context.Context
	release <-chan struct{}
}

func (c heldDoneContext) Done() <-chan struct{} {
	<-c.release
	return c.Context.Done()
}

func TestEmailQueuePerEngineResultWaitKeepsItsAge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o := NewOrchestrator(nil, time.Hour)
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		release := make(chan struct{})
		results := make(chan engineScanResult, 1)
		var wg sync.WaitGroup
		o.startScan(heldDoneContext{ctx, release}, &mockScanner{name: "clean", available: true}, "part", results, &wg)
		synctest.Wait()
		if s := emailQueue(t, o); s.Depth != 1 || s.InFlight != 0 || s.Status != "ok" || len(results) != 0 {
			t.Fatalf("engine result before wrapper consumption: %+v buffered=%d", s, len(results))
		}
		time.Sleep(31 * time.Second)
		close(release)
		wg.Wait()
		synctest.Wait()
		time.Sleep(30 * time.Second)
		if s := emailQueue(t, o); s.Depth != 1 || s.InFlight != 0 || s.Reason != "backlog_lag" || s.LagSeconds != 61 || len(results) != 1 {
			t.Fatalf("buffer transfer reset pending age: %+v buffered=%d", s, len(results))
		}
		r := <-results
		r.work.received()
		r.work.finishDelivery(true)
		if s := emailQueue(t, o); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
			t.Fatalf("buffered result drain: %+v", s)
		}
	})
}

func TestEmailQueueLateDispatchKeepsOriginalDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o := NewOrchestrator(nil, time.Hour)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		release := make(chan struct{})
		results := make(chan engineScanResult, 1)
		var wg sync.WaitGroup
		time.Sleep(9 * time.Second)
		o.startScan(ctx, controlledScanner{"late", func() (Verdict, error) { <-release; return Verdict{}, nil }}, "part", results, &wg)
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		wg.Wait()
		r := <-results
		if !r.timedOut || r.engine != "late" {
			t.Fatalf("late dispatch borrowed a fresh timeout: %+v", r)
		}
		r.work.received()
		r.work.finishDelivery(true)
		if s := emailQueue(t, o); s.InFlight != 1 || s.Depth != 0 || s.Reason != "processing_lag" || s.ProcessingSeconds != 2 || s.DroppedTotal != 1 {
			t.Fatalf("late dispatch hid expired work: %+v", s)
		}
		close(release)
		synctest.Wait()
		if s := emailQueue(t, o); s.InFlight != 0 || s.Depth != 0 || s.DroppedTotal != 1 {
			t.Fatalf("late dispatch completion: %+v", s)
		}
	})
}

type exitingScanError struct{}

func (exitingScanError) Error() string {
	runtime.Goexit()
	return "unreachable"
}

func TestEmailQueueAbandonedConsumerRetainsEngine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		o := NewOrchestrator([]Scanner{
			controlledScanner{"error", func() (Verdict, error) { return Verdict{}, exitingScanError{} }},
			controlledScanner{"running", func() (Verdict, error) { <-release; return Verdict{}, errors.New("late failure") }},
		}, time.Hour)
		consumerDone := make(chan struct{})
		go func() {
			defer close(consumerDone)
			o.ScanParts("controlled", []emime.ExtractedPart{{Filename: "part"}}, false)
			t.Error("consumer unexpectedly survived abnormal result handling")
		}()
		<-consumerDone
		synctest.Wait()
		if s := emailQueue(t, o); s.Depth != 0 || s.InFlight != 1 || s.DroppedTotal != 2 {
			t.Fatalf("abandoned results hid engine or counted error twice: %+v", s)
		}
		close(release)
		synctest.Wait()
		if s := emailQueue(t, o); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 2 {
			t.Fatalf("late failure after consumer exit: %+v", s)
		}
	})
}
