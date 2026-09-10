package checks

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func emailHashQueueRows(t *testing.T, p *emailHashPool, now time.Time) (queuehealth.Status, queuehealth.Status) {
	t.Helper()
	result := make(chan map[string]queuehealth.Status, 1)
	go func() { result <- p.QueueStatuses(now) }()
	select {
	case rows := <-result:
		hashes, haveHashes := rows["hashes"]
		waiting, haveWaiting := rows["waiting"]
		if len(rows) != 2 || !haveHashes || !haveWaiting || hashes.Capacity != cap(p.slots) || waiting.Capacity != 0 || !waiting.CapacityUnavailable {
			t.Fatalf("password queue capacity evidence = %+v", rows)
		}
		return hashes, waiting
	case <-time.After(time.Second):
		t.Fatal("password queue health waited for verification work")
		return queuehealth.Status{}, queuehealth.Status{}
	}
}

func TestEmailHashQueuesRetainCanceledWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newEmailHashPool(3)
		release := make(chan struct{})
		releaseWorkers := sync.OnceFunc(func() { close(release) })
		defer releaseWorkers()
		var calls atomic.Int32
		match := func(string) (bool, error) { calls.Add(1); <-release; return true, nil }
		candidate := rand.Text()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var callers sync.WaitGroup
		for range 3 {
			callers.Go(func() {
				if _, err := p.matches(ctx, match, candidate); !errors.Is(err, context.Canceled) {
					t.Error("canceled caller did not return cancellation")
				}
			})
		}
		synctest.Wait()
		cancel()
		callers.Wait()
		hashes, waiting := emailHashQueueRows(t, p, time.Now())
		if calls.Load() != 3 || len(p.slots) != 3 || hashes.InFlight != 3 || hashes.Depth != 0 || hashes.DroppedTotal != 0 || waiting.Depth != 0 || waiting.DroppedTotal != 0 {
			t.Fatalf("canceled callers concealed occupied hash slots: hashes=%+v waiting=%+v calls=%d", hashes, waiting, calls.Load())
		}
		waitCtx, cancelWait := context.WithCancel(context.Background())
		defer cancelWait()
		done := make(chan error, 5)
		for range 5 {
			go func() { _, err := p.matches(waitCtx, match, candidate); done <- err }()
		}
		synctest.Wait()
		hashes, waiting = emailHashQueueRows(t, p, time.Now())
		if waiting.Depth != 5 || waiting.InFlight != 0 || hashes.InFlight != 3 || calls.Load() != 3 {
			t.Fatalf("waiting caller escaped admission: hashes=%+v waiting=%+v calls=%d", hashes, waiting, calls.Load())
		}
		cancelWait()
		for range 5 {
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatal("waiting caller did not cancel")
			}
		}
		_, waiting = emailHashQueueRows(t, p, time.Now())
		if waiting.Depth != 0 || waiting.DroppedTotal != 0 {
			t.Fatalf("withdrawn demand counted as lost work: %+v", waiting)
		}
		deadlineCtx, cancelDeadline := context.WithTimeout(context.Background(), time.Second)
		defer cancelDeadline()
		if _, err := p.matches(deadlineCtx, match, candidate); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("waiting caller did not reach its deadline")
		}
		hashes, waiting = emailHashQueueRows(t, p, time.Now())
		if waiting.Depth != 0 || waiting.DroppedTotal != 1 || hashes.InFlight != 3 || hashes.DroppedTotal != 0 || calls.Load() != 3 {
			t.Fatalf("waiting timeout accounting: hashes=%+v waiting=%+v calls=%d", hashes, waiting, calls.Load())
		}
		time.Sleep(6 * time.Minute)
		hashes, _ = emailHashQueueRows(t, p, time.Now())
		if hashes.Reason != "processing_lag" || hashes.InFlight != 3 || hashes.ProcessingSeconds != 361 {
			t.Fatalf("abandoned hash work did not report its age: %+v", hashes)
		}
		releaseWorkers()
		synctest.Wait()
		if matched, err := p.matches(context.Background(), match, candidate); err != nil || !matched {
			t.Fatal("hash pool did not accept work after recovery")
		}
		synctest.Wait()
		hashes, waiting = emailHashQueueRows(t, p, time.Now())
		if hashes.Status != "ok" || hashes.InFlight != 0 || hashes.Depth != 0 || hashes.DroppedTotal != 0 || waiting.Status != "ok" || waiting.Depth != 0 || waiting.DroppedTotal != 1 || len(p.slots) != 0 || calls.Load() != 4 {
			t.Fatalf("hash pool did not recover: hashes=%+v waiting=%+v calls=%d", hashes, waiting, calls.Load())
		}
	})
}

func TestEmailHashQueuesLateCompletionCountsOnce(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		for _, outcome := range []string{"success", "failure", "goexit"} {
			name := "canceled/" + outcome
			if deadline {
				name = "deadline/" + outcome
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					p := newEmailHashPool(1)
					release := make(chan struct{})
					releaseWorker := sync.OnceFunc(func() { close(release) })
					defer releaseWorker()
					match := func(string) (bool, error) {
						<-release
						if outcome == "goexit" {
							runtime.Goexit()
						}
						if outcome == "failure" {
							return false, errors.New("verification unavailable")
						}
						return true, nil
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if deadline {
						ctx, cancel = context.WithTimeout(ctx, time.Second)
						defer cancel()
					}
					done := make(chan error, 1)
					go func() { _, err := p.matches(ctx, match, rand.Text()); done <- err }()
					synctest.Wait()
					wantErr, wantLoss := context.Canceled, uint64(0)
					if deadline {
						time.Sleep(2 * time.Second)
						wantErr, wantLoss = context.DeadlineExceeded, 1
					} else {
						cancel()
					}
					if err := <-done; !errors.Is(err, wantErr) {
						t.Fatal("caller did not return its context error")
					}
					hashes, waiting := emailHashQueueRows(t, p, time.Now())
					if hashes.InFlight != 1 || hashes.DroppedTotal != wantLoss || len(p.slots) != 1 || waiting.Depth != 0 || waiting.DroppedTotal != 0 {
						t.Fatalf("caller exit concealed KDF: hashes=%+v waiting=%+v", hashes, waiting)
					}
					releaseWorker()
					synctest.Wait()
					if outcome != "success" {
						wantLoss = 1
					}
					hashes, _ = emailHashQueueRows(t, p, time.Now())
					if hashes.Depth != 0 || hashes.InFlight != 0 || hashes.DroppedTotal != wantLoss || len(p.slots) != 0 {
						t.Fatalf("late completion ownership or loss: %+v occupied=%d", hashes, len(p.slots))
					}
				})
			})
		}
	}
}

func TestEmailHashQueuesRetainBufferedResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newEmailHashPool(1)
		work, err := p.acquire(context.Background())
		if err != nil {
			t.Fatal("initial admission failed")
		}
		releaseCaller := sync.OnceFunc(work.release)
		defer releaseCaller()
		done := make(chan emailHashResult, 1)
		workerDone := make(chan struct{})
		go func() {
			defer close(workerDone)
			p.execute(work, func(string) (bool, error) { return true, nil }, rand.Text(), done)
		}()
		<-workerDone
		hashes, _ := emailHashQueueRows(t, p, time.Now())
		if hashes.InFlight != 1 || hashes.DroppedTotal != 0 || len(p.slots) != 1 || len(done) != 1 {
			t.Fatalf("unread result released its slot: %+v occupied=%d results=%d", hashes, len(p.slots), len(done))
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var called atomic.Bool
		if _, err := p.matches(ctx, func(string) (bool, error) { called.Store(true); return false, nil }, rand.Text()); !errors.Is(err, context.DeadlineExceeded) || called.Load() {
			t.Fatal("unread result allowed another KDF into the pool")
		}
		got := <-done
		if !got.match || got.err != nil {
			t.Fatal("buffered result was changed")
		}
		releaseCaller()
		hashes, waiting := emailHashQueueRows(t, p, time.Now())
		if hashes.InFlight != 0 || hashes.Depth != 0 || hashes.DroppedTotal != 0 || waiting.Depth != 0 || waiting.DroppedTotal != 1 || len(p.slots) != 0 {
			t.Fatalf("result release did not settle: hashes=%+v waiting=%+v", hashes, waiting)
		}
	})
}

func TestEmailHashQueuesConcurrentFailuresAreSafe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newEmailHashPool(3)
		candidate := rand.Text()
		var calls atomic.Int32
		match := func(string) (bool, error) { calls.Add(1); return false, errors.New(candidate) }
		var wg sync.WaitGroup
		for range 12 {
			wg.Go(func() {
				if got, err := p.matches(context.Background(), match, candidate); got || err != errEmailPasswordVerify {
					t.Error("verification did not return its sanitized error")
				}
			})
		}
		wg.Wait()
		synctest.Wait()
		hashes, waiting := emailHashQueueRows(t, p, time.Now())
		if calls.Load() != 12 || hashes.DroppedTotal != 12 || hashes.Status != "degraded" || hashes.Reason != "dropped_work" || hashes.Depth != 0 || hashes.InFlight != 0 || waiting.DroppedTotal != 0 || waiting.Depth != 0 || len(p.slots) != 0 {
			t.Fatalf("concurrent error accounting: hashes=%+v waiting=%+v calls=%d", hashes, waiting, calls.Load())
		}
		encoded, err := json.Marshal(p.QueueStatuses(time.Now()))
		if err != nil || strings.Contains(string(encoded), candidate) {
			t.Fatal("health exposed verification input")
		}
		time.Sleep(time.Minute)
		hashes, waiting = emailHashQueueRows(t, p, time.Now())
		if hashes.Status != "ok" || hashes.DroppedTotal != 12 || waiting.Status != "ok" {
			t.Fatalf("error window did not recover: hashes=%+v waiting=%+v", hashes, waiting)
		}
	})
}

func TestEmailHashQueuesIgnoreRejectedInput(t *testing.T) {
	p := newEmailHashPool(3)
	var calls atomic.Int32
	match := func(string) (bool, error) { calls.Add(1); return false, nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.matches(ctx, match, rand.Text()); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled request was accepted")
	}
	for _, candidate := range []string{strings.Repeat(rand.Text(), maxEmailCandidateBytes), rand.Text() + "\x00"} {
		if _, err := p.matches(context.Background(), match, candidate); err != errEmailCandidate {
			t.Fatal("invalid candidate was accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected input reached the KDF")
	}
	hashes, waiting := emailHashQueueRows(t, p, time.Now())
	if hashes.Depth != 0 || hashes.InFlight != 0 || hashes.DroppedTotal != 0 || waiting.Depth != 0 || waiting.DroppedTotal != 0 {
		t.Fatalf("rejected input created work: hashes=%+v waiting=%+v", hashes, waiting)
	}
}

func TestEmailHashQueuesUseAuditLagBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newEmailHashPool(1)
		release := make(chan struct{})
		releaseWorker := sync.OnceFunc(func() { close(release) })
		defer releaseWorker()
		match := func(string) (bool, error) { <-release; return false, nil }
		go func() { _, _ = p.matches(context.Background(), match, rand.Text()) }()
		synctest.Wait()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _, _ = p.matches(ctx, match, rand.Text()) }()
		synctest.Wait()
		time.Sleep(4 * time.Minute)
		hashes, waiting := emailHashQueueRows(t, p, time.Now())
		if hashes.Reason != "queue_full" || hashes.ProcessingSeconds != 240 || waiting.Status != "ok" || waiting.LagSeconds != 240 || waiting.Depth != 1 {
			t.Fatalf("allowed audit work declared stalled: hashes=%+v waiting=%+v", hashes, waiting)
		}
		time.Sleep(time.Minute)
		hashes, waiting = emailHashQueueRows(t, p, time.Now())
		if hashes.Reason != "processing_lag" || hashes.ProcessingSeconds != 300 || waiting.Reason != "backlog_lag" || waiting.LagSeconds != 300 {
			t.Fatalf("audit budget did not bound stalled work: hashes=%+v waiting=%+v", hashes, waiting)
		}
		cancel()
		releaseWorker()
		synctest.Wait()
		hashes, waiting = emailHashQueueRows(t, p, time.Now())
		if hashes.InFlight != 0 || hashes.Depth != 0 || waiting.Depth != 0 || hashes.DroppedTotal != 0 || waiting.DroppedTotal != 0 {
			t.Fatalf("canceled lagging work did not settle: hashes=%+v waiting=%+v", hashes, waiting)
		}
	})
}
