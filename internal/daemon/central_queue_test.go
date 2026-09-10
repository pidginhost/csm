package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/reporting"
)

func TestCentralQueuePublishedBeforeLoopStarts(t *testing.T) {
	previous := alert.CentralHook
	t.Cleanup(func() { alert.SetCentralHook(previous) })
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSM_TEST_CENTRAL_QUEUE_PUB", hex.EncodeToString(pub))
	cfg := &config.Config{}
	cfg.Reputation.Central.Enabled = true
	cfg.Reputation.Central.SetURL = "https://central.example/decisions"
	cfg.Reputation.Central.PubkeyEnv = "CSM_TEST_CENTRAL_QUEUE_PUB"
	d := New(cfg, nil, nil, "")
	if loop := d.startCentralConsume(); loop == nil {
		t.Fatal("configured central consumer did not start")
	}
	got, exists := d.QueueStatuses()["central.actions"]
	if !exists || got.Capacity != 1024 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 || got.Status != "ok" {
		t.Fatalf("central actions are missing before the refresh loop: exists=%v status=%+v", exists, got)
	}
}

func TestCentralQueueRetainsBacklogDuringRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stop, release := make(chan struct{}), make(chan struct{})
		stopLoop := sync.OnceFunc(func() { close(stop) })
		releaseRefresh := sync.OnceFunc(func() { close(release) })
		var performed []string
		consumer := newCentralActionConsumer(stop, 3, time.Hour, func(context.Context) error {
			<-release
			return nil
		}, func(a centralQueuedAction) error {
			performed = append(performed, a.ip)
			return nil
		})
		for i, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"} {
			if accepted := consumer.enqueue(centralQueuedAction{decision: reporting.DecisionBlock, ip: ip}); accepted != (i < 3) {
				t.Fatalf("admission %d changed the queue cap: accepted=%v", i, accepted)
			}
		}
		done := make(chan struct{})
		go func() { defer close(done); consumer.run() }()
		defer func() { stopLoop(); releaseRefresh(); <-done }()
		synctest.Wait()
		time.Sleep(61 * time.Second)
		got := consumer.QueueStatuses(time.Now())["actions"]
		if got.Depth != 3 || got.Capacity != 3 || got.InFlight != 0 || got.DroppedTotal != 2 || got.LagSeconds != 61 || got.Status != "degraded" {
			t.Fatalf("feed refresh concealed queued actions: %+v", got)
		}
		releaseRefresh()
		synctest.Wait()
		if !reflect.DeepEqual(performed, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}) {
			t.Fatalf("refresh lost, repeated or reordered admitted actions: %v", performed)
		}
		stopLoop()
		<-done
		got = consumer.QueueStatuses(time.Now())["actions"]
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 2 || got.Status != "ok" {
			t.Fatalf("drain or shutdown reporting erased prior loss: %+v", got)
		}
	})
}

func TestCentralQueueShutdownRejectsCapturedProducers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stop, release := make(chan struct{}), make(chan struct{})
		stopLoop := sync.OnceFunc(func() { close(stop) })
		releaseAction := sync.OnceFunc(func() { close(release) })
		var calls atomic.Int32
		consumer := newCentralActionConsumer(stop, 3, time.Hour, func(context.Context) error { return nil }, func(centralQueuedAction) error {
			calls.Add(1)
			<-release
			return errors.New("block failed")
		})
		done := make(chan struct{})
		go func() { defer close(done); consumer.run() }()
		defer func() { stopLoop(); releaseAction(); <-done }()
		action := centralQueuedAction{decision: reporting.DecisionBlock, ip: "192.0.2.1"}
		if !consumer.enqueue(action) {
			t.Fatal("first action refused")
		}
		synctest.Wait()
		for range 3 {
			if !consumer.enqueue(action) {
				t.Fatal("waiting action refused")
			}
		}
		time.Sleep(61 * time.Second)
		got := consumer.QueueStatuses(time.Now())["actions"]
		if got.Depth != 3 || got.InFlight != 1 || got.LagSeconds != 61 || got.ProcessingSeconds != 61 || got.Status != "degraded" {
			t.Fatalf("blocked action concealed waiting or running work: %+v", got)
		}
		captured := consumer.enqueue
		stopLoop()
		if captured(action) {
			t.Fatal("captured producer accepted new action after shutdown began")
		}
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("shutdown returned while an action still ran")
		default:
		}
		releaseAction()
		<-done
		got = consumer.QueueStatuses(time.Now())["actions"]
		if calls.Load() != 1 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 5 {
			t.Fatalf("shutdown ran abandoned actions or lost their evidence: calls=%d status=%+v", calls.Load(), got)
		}
		if captured(action) {
			t.Fatal("captured producer accepted action after loop returned")
		}
		if got = consumer.QueueStatuses(time.Now())["actions"]; got.DroppedTotal != 6 {
			t.Fatalf("late producer loss missing after loop returned: %+v", got)
		}
	})
}

func TestCentralQueuePanicSettlesOwnedAndAbandonedWork(t *testing.T) {
	stop := make(chan struct{})
	consumer := newCentralActionConsumer(stop, 3, time.Hour, func(context.Context) error { return nil }, func(centralQueuedAction) error {
		panic("action failed")
	})
	for range 3 {
		if !consumer.enqueue(centralQueuedAction{decision: reporting.DecisionBlock, ip: "192.0.2.1"}) {
			t.Fatal("initial action refused")
		}
	}
	var caught any
	func() { defer func() { caught = recover() }(); consumer.run() }()
	if caught != "action failed" {
		t.Fatalf("action panic was concealed: %v", caught)
	}
	got := consumer.QueueStatuses(time.Now())["actions"]
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 {
		t.Fatalf("panic lost owned or abandoned actions: %+v", got)
	}
	if consumer.enqueue(centralQueuedAction{decision: reporting.DecisionBlock, ip: "192.0.2.1"}) {
		t.Fatal("failed loop continued accepting actions")
	}
}

func TestCentralQueueConcurrentShutdownConservesActions(t *testing.T) {
	stop := make(chan struct{})
	consumer := newCentralActionConsumer(stop, 4, time.Hour, func(context.Context) error { return nil }, func(centralQueuedAction) error {
		return errors.New("action failed")
	})
	done := make(chan struct{})
	go func() { defer close(done); consumer.run() }()
	start := make(chan struct{})
	var producers sync.WaitGroup
	for range 4 {
		producers.Go(func() {
			<-start
			for range 64 {
				consumer.enqueue(centralQueuedAction{decision: reporting.DecisionBlock, ip: "192.0.2.1"})
			}
		})
	}
	producers.Go(func() { <-start; close(stop) })
	close(start)
	producers.Wait()
	<-done
	got := consumer.QueueStatuses(time.Now())["actions"]
	if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 256 {
		t.Fatalf("concurrent admission and shutdown lost incomplete actions: %+v", got)
	}
}

type centralQueueBlocker struct{ err error }

func (b centralQueueBlocker) BlockIP(string, string, time.Duration) error { return b.err }
func (centralQueueBlocker) UnblockIP(string) error                        { return nil }
func (centralQueueBlocker) IsBlocked(string) bool                         { return false }

func TestCentralQueueActionErrorsRemainVisible(t *testing.T) {
	failed := errors.New("firewall unavailable")
	for _, tc := range []struct {
		name string
		err  error
		lost uint64
	}{
		{"failure", failed, 1},
		{"protected", firewall.ErrIPProtected, 0},
		{"no engine", checks.ErrNoIPBlocker, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{StatePath: t.TempDir()}
			previous := config.Active()
			config.SetActive(cfg)
			t.Cleanup(func() { config.SetActive(previous); checks.SetIPBlocker(nil) })
			if tc.err == checks.ErrNoIPBlocker {
				checks.SetIPBlocker(nil)
			} else {
				checks.SetIPBlocker(centralQueueBlocker{tc.err})
			}
			d := New(cfg, nil, nil, "")
			action := centralQueuedAction{decision: reporting.DecisionBlock, ip: "192.0.2.1"}
			if err := d.performCentralAction(action); !errors.Is(err, tc.err) {
				t.Fatalf("block refusal disappeared: got=%v want=%v", err, tc.err)
			}
			consumer := newCentralActionConsumer(d.stopCh, 1, time.Hour, func(context.Context) error { return nil }, func(a centralQueuedAction) error {
				defer close(d.stopCh)
				return d.performCentralAction(a)
			})
			if !consumer.enqueue(action) {
				t.Fatal("action refused")
			}
			consumer.run()
			got := consumer.QueueStatuses(time.Now())["actions"]
			if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != tc.lost {
				t.Fatalf("action failure and policy refusal conflated: %+v", got)
			}
		})
	}
}

func TestCentralQueueStopCancelsRefreshAndDiscardsBacklog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stop := make(chan struct{})
		var refreshed, performed int
		consumer := newCentralActionConsumer(stop, 2, time.Hour, func(ctx context.Context) error {
			refreshed++
			<-ctx.Done()
			return ctx.Err()
		}, func(centralQueuedAction) error { performed++; return nil })
		for range 2 {
			if !consumer.enqueue(centralQueuedAction{decision: reporting.DecisionBlock, ip: "192.0.2.1"}) {
				t.Fatal("initial action refused")
			}
		}
		done := make(chan struct{})
		go func() { defer close(done); consumer.run() }()
		synctest.Wait()
		close(stop)
		<-done
		got := consumer.QueueStatuses(time.Now())["actions"]
		if refreshed != 1 || performed != 0 || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 2 {
			t.Fatalf("refresh cancellation started or concealed abandoned actions: refresh=%d performed=%d status=%+v", refreshed, performed, got)
		}
	})
}
