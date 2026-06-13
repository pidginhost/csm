package webui

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/broadcast"
	"github.com/pidginhost/csm/internal/config"
)

func TestApiEvents_StreamsFindings(t *testing.T) {
	bus := broadcast.NewBus(8)
	defer bus.Close()

	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "t", Token: "secret", Scope: "read"}}
	s.SetFindingBus(bus)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer secret")
	rec := newDeadlineRecorder()

	done := make(chan struct{})
	go func() {
		s.requireRead(http.HandlerFunc(s.apiEvents)).ServeHTTP(rec, req)
		close(done)
	}()

	waitForRecorderFlush(t, rec, 1)
	if got := rec.headerValue("Content-Type"); got != "text/event-stream" {
		t.Fatalf("expected SSE content type, got %q", got)
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		bus.Publish(alert.Finding{Check: "x", Severity: alert.High})
	}()

	waitForRecorderBodyContains(t, rec, `"check":"x"`)
	cancel()
	waitForHandlerDone(t, done)
}

func TestApiEvents_NilBusReturns503(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "t", Token: "secret", Scope: "read"}}
	// Do NOT call SetFindingBus — leave nil

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	s.requireRead(http.HandlerFunc(s.apiEvents)).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestApiEvents_Returns503WhenSubscriberCapIsFull(t *testing.T) {
	bus := broadcast.NewBus(8)
	defer bus.Close()
	bus.SetMaxSubscribers(1)
	sub, ok := bus.TrySubscribe()
	if !ok {
		t.Fatal("expected first subscription to reserve the only slot")
	}
	defer bus.Unsubscribe(sub)

	s := &Server{cfg: &config.Config{}}
	s.SetFindingBus(bus)

	rec := httptest.NewRecorder()
	s.apiEvents(rec, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when subscriber cap is full, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "too many event stream subscribers") {
		t.Fatalf("unexpected response body: %q", rec.Body.String())
	}
}

func TestApiEvents_SetsFiniteDeadlineBeforeEachWrite(t *testing.T) {
	bus := broadcast.NewBus(8)
	defer bus.Close()

	s := &Server{cfg: &config.Config{}, pruneDone: make(chan struct{})}
	s.SetFindingBus(bus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
	rec := newDeadlineRecorder()

	done := make(chan struct{})
	go func() {
		s.apiEvents(rec, req)
		close(done)
	}()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(time.Second)
	for {
		select {
		case <-ticker.C:
			bus.Publish(alert.Finding{Check: "x", Severity: alert.High})
			body, _, _ := rec.snapshot()
			if strings.Contains(body, `"check":"x"`) {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("SSE handler did not exit after request cancellation")
				}
				_, calls, flushes := rec.snapshot()
				if len(calls) < 3 {
					t.Fatalf("expected initial and event write deadlines, got %d", len(calls))
				}
				if flushes < 2 {
					t.Fatalf("expected initial and event flushes, got %d", flushes)
				}
				for _, call := range calls {
					if call.deadline.IsZero() {
						t.Fatal("deadline was zero")
					}
					delta := call.deadline.Sub(call.at)
					if delta < sseWriteTimeout-500*time.Millisecond || delta > sseWriteTimeout+100*time.Millisecond {
						t.Fatalf("deadline duration = %s, want about %s", delta, sseWriteTimeout)
					}
				}
				return
			}
		case <-timeout:
			cancel()
			t.Fatal("timed out waiting for SSE data")
		}
	}
}

func TestApiEvents_ShutdownClosesActiveStream(t *testing.T) {
	bus := broadcast.NewBus(8)
	defer bus.Close()

	s := &Server{cfg: &config.Config{}, pruneDone: make(chan struct{})}
	s.SetFindingBus(bus)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	rec := newDeadlineRecorder()

	streamDone := make(chan struct{})
	go func() {
		s.apiEvents(rec, req)
		close(streamDone)
	}()

	waitForRecorderFlush(t, rec, 1)
	if got := rec.headerValue("Content-Type"); got != "text/event-stream" {
		t.Fatalf("expected SSE content type, got %q", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Run Shutdown under an outer watchdog. A regression where Shutdown blocks
	// on the still-open SSE stream must fail fast and specifically; the ctx
	// deadline alone is not enough, because a Shutdown that ignores ctx would
	// hang the whole test binary until the global timeout instead of failing
	// here. The done channel distinguishes a clean return from a hang.
	shutdownErr := make(chan error, 1)
	go func() { shutdownErr <- s.Shutdown(ctx) }()
	select {
	case err := <-shutdownErr:
		if err != nil {
			t.Fatalf("shutdown with active SSE client: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return while an SSE client was connected")
	}
	waitForHandlerDone(t, streamDone)
}

func TestApiEvents_DeadlineUnsupportedReturns500(t *testing.T) {
	bus := broadcast.NewBus(8)
	defer bus.Close()

	s := &Server{cfg: &config.Config{}}
	s.SetFindingBus(bus)

	rec := httptest.NewRecorder()
	s.apiEvents(rec, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when write deadlines are unsupported, got %d", rec.Code)
	}
}

type deadlineCall struct {
	at       time.Time
	deadline time.Time
}

type deadlineRecorder struct {
	header    http.Header
	body      bytes.Buffer
	mu        sync.Mutex
	status    int
	flushes   int
	deadlines []deadlineCall
}

func newDeadlineRecorder() *deadlineRecorder {
	return &deadlineRecorder{header: make(http.Header)}
}

func (r *deadlineRecorder) Header() http.Header {
	return r.header
}

func (r *deadlineRecorder) WriteHeader(status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status == 0 {
		r.status = status
	}
}

func (r *deadlineRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(p)
}

func (r *deadlineRecorder) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status == 0 {
		r.status = http.StatusOK
	}
	r.flushes++
}

func (r *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deadlines = append(r.deadlines, deadlineCall{at: time.Now(), deadline: deadline})
	return nil
}

func (r *deadlineRecorder) snapshot() (string, []deadlineCall, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	deadlines := append([]deadlineCall(nil), r.deadlines...)
	return r.body.String(), deadlines, r.flushes
}

func (r *deadlineRecorder) headerValue(key string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.header.Get(key)
}

func waitForRecorderFlush(t *testing.T, rec *deadlineRecorder, minFlushes int) {
	t.Helper()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(time.Second)
	for {
		select {
		case <-ticker.C:
			_, _, flushes := rec.snapshot()
			if flushes >= minFlushes {
				return
			}
		case <-timeout:
			_, _, flushes := rec.snapshot()
			t.Fatalf("timed out waiting for %d flushes, got %d", minFlushes, flushes)
		}
	}
}

func waitForRecorderBodyContains(t *testing.T, rec *deadlineRecorder, needle string) {
	t.Helper()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(time.Second)
	for {
		select {
		case <-ticker.C:
			body, _, _ := rec.snapshot()
			if strings.Contains(body, needle) {
				return
			}
		case <-timeout:
			body, _, _ := rec.snapshot()
			t.Fatalf("timed out waiting for body containing %q; body=%q", needle, body)
		}
	}
}

func waitForHandlerDone(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SSE handler did not exit")
	}
}
