package checks

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func TestAutoBlockRetryDirectCompletionIsPreserved(t *testing.T) {
	for _, mode := range []string{"saved", "failed-write", "bookkeeping-panic"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			cfg := autoBlockQueueFixture(t, func() error { calls++; return nil })
			now := time.Now().Truncate(time.Second)
			setAutoBlockNow(t, now)
			const ip = "192.0.2.110"
			if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{
				{Check: "wp_login_bruteforce", Severity: alert.Critical, IP: ip, Reason: "eligible retry", QueuedAt: now.Add(-time.Minute)},
				{Check: "wp_login_bruteforce", Severity: alert.Critical, IP: ip, Reason: "already expired before direct decision", QueuedAt: now.Add(-3 * time.Hour)},
				{Check: "wp_login_bruteforce", Severity: alert.Critical, IP: "192.0.2.111", Reason: "unrelated retry", QueuedAt: now.Add(-time.Minute)},
			}}); err != nil {
				t.Fatal(err)
			}
			var restoreWrite func()
			if mode == "failed-write" {
				restoreWrite = failRetryWrite(t, cfg.StatePath)
			}
			if mode == "bookkeeping-panic" {
				SetIPBlocker(retryCleanupBlocker{
					retryQueueBlocker: retryQueueBlocker{block: func(string) error { calls++; return nil }},
					cover:             func() bool { panic("direct bookkeeping fixture") },
				})
			}
			var result ApplyBlockResult
			var returned error
			var recovered any
			captureStderr(t, func() {
				defer func() { recovered = recover() }()
				result, returned = ApplyBlock(cfg, ApplyBlockRequest{IP: ip, Reason: "direct decision", TTL: time.Hour, Source: BlockSourceCentral})
			})
			if calls != 1 {
				t.Fatalf("direct attempt count=%d, want1", calls)
			}
			if mode == "bookkeeping-panic" {
				if recovered != "direct bookkeeping fixture" {
					t.Fatalf("panic changed: %v", recovered)
				}
			} else if recovered != nil || returned != nil || result.Outcome != firewall.BlockOutcomeLive || len(result.Findings) != 1 {
				t.Fatalf("direct result changed: result=%+v err=%v panic=%v", result, returned, recovered)
			}
			if restoreWrite != nil {
				restoreWrite()
			}
			SetIPBlocker(retryQueueBlocker{block: func(string) error { t.Error("expired retry reached firewall"); return nil }})
			autoBlockNow = func() time.Time { return now.Add(maxPendingAge + time.Second) }
			AutoBlockIPs(cfg, nil)
			pending, candidates := retryQueueRows(t, time.Now())
			// The already expired record and unrelated IP were never completed;
			// the still-eligible record completed via the direct source.
			if pending.Depth != 0 || pending.InFlight != 0 || pending.DroppedTotal != 2 || candidates.DroppedTotal != 0 {
				t.Fatalf("direct success became queued loss: pending=%+v candidates=%+v", pending, candidates)
			}
		})
	}
}

type retryClassificationError struct {
	once             sync.Once
	entered, release chan struct{}
}

func (*retryClassificationError) Error() string { return "synthetic classification delay" }
func (e *retryClassificationError) Is(error) bool {
	e.once.Do(func() { close(e.entered); <-e.release })
	return false
}

func TestAutoBlockRetryErrorClassificationCannotBlockHealth(t *testing.T) {
	classification := &retryClassificationError{entered: make(chan struct{}), release: make(chan struct{})}
	cfg := autoBlockQueueFixture(t, func() error { return classification })
	if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{Check: "wp_login_bruteforce", Severity: alert.Critical, IP: "192.0.2.112", Reason: "retry", QueuedAt: time.Now()}}}); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	unblock := func() { once.Do(func() { close(classification.release) }) }
	done := make(chan struct{})
	go func() { defer close(done); AutoBlockIPs(cfg, nil) }()
	defer func() {
		unblock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("retry did not join")
		}
	}()
	select {
	case <-classification.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("error classification not reached")
	}
	health := make(chan map[string]queuehealth.Status, 1)
	go func() { health <- AutoBlockQueueStatuses(time.Now()) }()
	read := false
	defer func() {
		unblock()
		if !read {
			select {
			case <-health:
			case <-time.After(3 * time.Second):
				t.Error("health reader did not join")
			}
		}
	}()
	select {
	case rows := <-health:
		read = true
		if rows["pending"].InFlight != 1 || rows["candidates"].InFlight != 1 || rows["active"].InFlight != 1 {
			t.Fatalf("classification work lost its actual owner: %+v", rows)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("error classification held the health lock")
	}
	unblock()
	<-done
	pending, candidates := retryQueueRows(t, time.Now())
	if pending.Depth != 1 || pending.Reason != "retry_failed" || pending.DroppedTotal != 0 || candidates.DroppedTotal != 0 {
		t.Fatalf("classified error lost retained retry: pending=%+v candidates=%+v", pending, candidates)
	}
}

func TestAutoBlockRetryDirectAttemptKeepsOriginalEligibility(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		cfg := autoBlockQueueFixture(t, func() error { calls++; time.Sleep(2 * time.Second); return nil })
		now := time.Now()
		const ip = "192.0.2.113"
		if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{Check: "wp_login_bruteforce", Severity: alert.Critical, IP: ip, Reason: "eligible at attempt", QueuedAt: now.Add(-maxPendingAge + time.Second)}}}); err != nil {
			t.Fatal(err)
		}
		result, err := ApplyBlock(cfg, ApplyBlockRequest{IP: ip, Reason: "direct decision", TTL: time.Hour, Source: BlockSourceCentral})
		if err != nil || result.Outcome != firewall.BlockOutcomeLive || calls != 1 {
			t.Fatalf("direct attempt failed: result=%+v err=%v calls=%d", result, err, calls)
		}
		AutoBlockIPs(cfg, nil)
		pending, candidates := retryQueueRows(t, time.Now())
		if calls != 1 || pending.Depth != 0 || pending.DroppedTotal != 0 || candidates.DroppedTotal != 0 {
			t.Fatalf("late success forgot eligibility at actual attempt: calls=%d pending=%+v candidates=%+v", calls, pending, candidates)
		}
	})
}
