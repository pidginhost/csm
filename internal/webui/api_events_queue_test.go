package webui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/broadcast"
	"github.com/pidginhost/csm/internal/config"
)

type failedEventFlush struct {
	*deadlineRecorder
	flushCalls int
	failAt     int
}

func (r *failedEventFlush) FlushError() error {
	r.Flush()
	r.flushCalls++
	if r.flushCalls == r.failAt {
		return errors.New("client disconnected during flush")
	}
	return nil
}

func TestAPIEventsStopsAfterFailedFlush(t *testing.T) {
	for _, stage := range []string{"initial", "event", "keepalive"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bus := broadcast.NewBus(2)
				defer bus.Close()
				bus.SetMaxSubscribers(1)
				s := &Server{cfg: &config.Config{}}
				s.SetFindingBus(bus)
				ctx, cancel := context.WithCancel(context.Background())
				req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
				failAt := 2
				if stage == "initial" {
					failAt = 1
				}
				rec := &failedEventFlush{deadlineRecorder: newDeadlineRecorder(), failAt: failAt}
				done := make(chan struct{})
				go func() { defer close(done); s.apiEvents(rec, req) }()
				defer func() { cancel(); <-done }()
				synctest.Wait()
				switch stage {
				case "event":
					bus.Publish(alert.Finding{Check: "test"})
				case "keepalive":
					time.Sleep(25 * time.Second)
				}
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("event stream ignored a failed client flush")
				}
				if rec.flushCalls != failAt {
					t.Fatalf("flush calls = %d, want %d", rec.flushCalls, failAt)
				}
				if sub, ok := bus.TrySubscribe(); !ok {
					t.Fatal("failed stream retained its subscriber slot")
				} else {
					bus.Unsubscribe(sub)
				}
			})
		})
	}
}

type blockedEventWriter struct {
	*deadlineRecorder
	writeBlocked bool
	flushBlocked int
	flushCalls   int
	entered      chan struct{}
	release      chan struct{}
	err          error
}

func (w *blockedEventWriter) Write(p []byte) (int, error) {
	if w.writeBlocked && strings.HasPrefix(string(p), "data:") {
		close(w.entered)
		<-w.release
		return 0, w.err
	}
	return w.deadlineRecorder.Write(p)
}

func (w *blockedEventWriter) FlushError() error {
	w.flushCalls++
	if w.flushCalls == w.flushBlocked {
		close(w.entered)
		<-w.release
		return w.err
	}
	w.Flush()
	return nil
}

func TestAPIEventsCountsFailedDeliveryAndPending(t *testing.T) {
	for _, stage := range []string{"initial", "write", "flush", "keepalive"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bus := broadcast.NewBus(2)
				defer bus.Close()
				s := &Server{cfg: &config.Config{}}
				s.SetFindingBus(bus)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				w := &blockedEventWriter{deadlineRecorder: newDeadlineRecorder(), entered: make(chan struct{}), release: make(chan struct{}), err: errors.New("stream write failed")}
				switch stage {
				case "initial":
					w.flushBlocked = 1
				case "write":
					w.writeBlocked = true
				default:
					w.flushBlocked = 2
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					s.apiEvents(w, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx))
				}()
				defer func() {
					select {
					case <-w.release:
					default:
						close(w.release)
					}
					cancel()
					<-done
				}()
				synctest.Wait()
				running := 0
				if stage == "keepalive" {
					time.Sleep(25 * time.Second)
				}
				if stage == "write" || stage == "flush" {
					running = 1
					bus.Publish(alert.Finding{Check: "active"})
				}
				<-w.entered
				for range 2 {
					bus.Publish(alert.Finding{Check: "pending"})
				}
				q := bus.QueueStatuses(time.Now())["deliveries"]
				if q.Capacity != 2 || q.Depth != 2 || q.InFlight != running || q.DroppedTotal != 0 {
					t.Fatalf("blocked stream = %+v", q)
				}
				time.Sleep(4 * time.Second)
				q = bus.QueueStatuses(time.Now())["deliveries"]
				if q.LagSeconds != 4 || q.ProcessingSeconds != float64(running*4) {
					t.Fatalf("stream ages = %+v", q)
				}
				close(w.release)
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("failed stream did not stop")
				}
				q = bus.QueueStatuses(time.Now())["deliveries"]
				if q.Capacity != 0 || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != uint64(2+running) {
					t.Fatalf("failed stream settlement = %+v", q)
				}
			})
		})
	}
}

func TestAPIEventsCancellationWithdrawsPendingDemand(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		name := "request"
		if shutdown {
			name = "shutdown"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bus := broadcast.NewBus(2)
				defer bus.Close()
				s := &Server{cfg: &config.Config{}, pruneDone: make(chan struct{})}
				s.SetFindingBus(bus)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				w := &blockedEventWriter{deadlineRecorder: newDeadlineRecorder(), writeBlocked: true, entered: make(chan struct{}), release: make(chan struct{}), err: errors.New("connection closed")}
				done := make(chan struct{})
				go func() {
					defer close(done)
					s.apiEvents(w, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx))
				}()
				defer func() {
					select {
					case <-w.release:
					default:
						close(w.release)
					}
					cancel()
					<-done
				}()
				synctest.Wait()
				bus.Publish(alert.Finding{})
				<-w.entered
				for range 2 {
					bus.Publish(alert.Finding{})
				}
				if shutdown {
					close(s.pruneDone)
				} else {
					cancel()
				}
				close(w.release)
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("canceled stream did not stop")
				}
				q := bus.QueueStatuses(time.Now())["deliveries"]
				if q.Capacity != 0 || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
					t.Fatalf("normal closure counted as failed delivery: %+v", q)
				}
			})
		})
	}
}

func TestAPIEventsEncodingFailureKeepsStreamUsable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bus := broadcast.NewBus(2)
		defer bus.Close()
		s := &Server{cfg: &config.Config{}}
		s.SetFindingBus(bus)
		ctx, cancel := context.WithCancel(context.Background())
		rec := newDeadlineRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.apiEvents(rec, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx))
		}()
		defer func() { cancel(); <-done }()
		synctest.Wait()
		bus.Publish(alert.Finding{Check: "invalid", Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)})
		bus.Publish(alert.Finding{Check: "valid"})
		synctest.Wait()
		body, _, flushes := rec.snapshot()
		if !strings.Contains(body, `"check":"valid"`) || strings.Contains(body, "invalid") || flushes != 2 {
			t.Fatalf("encoding recovery: body=%q flushes=%d", body, flushes)
		}
		q := bus.QueueStatuses(time.Now())["deliveries"]
		if q.Capacity != 2 || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 1 {
			t.Fatalf("encoding loss = %+v", q)
		}
		select {
		case <-done:
			t.Fatal("encoding error terminated the stream")
		default:
		}
	})
}
