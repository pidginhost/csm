package webui

import (
	"bufio"
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

	srv := httptest.NewServer(s.requireRead(http.HandlerFunc(s.apiEvents)))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("expected SSE content type, got %q", resp.Header.Get("Content-Type"))
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		bus.Publish(alert.Finding{Check: "x", Severity: alert.High})
	}()

	scanner := bufio.NewScanner(resp.Body)
	deadline := time.Now().Add(time.Second)
	gotData := false
	for scanner.Scan() && time.Now().Before(deadline) {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"check":"x"`) {
			gotData = true
			break
		}
	}
	if !gotData {
		t.Fatal("expected data line containing finding JSON")
	}
}

func TestApiEvents_NilBusReturns503(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "t", Token: "secret", Scope: "read"}}
	// Do NOT call SetFindingBus — leave nil

	srv := httptest.NewServer(s.requireRead(http.HandlerFunc(s.apiEvents)))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
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

	srv := httptest.NewServer(http.HandlerFunc(s.apiEvents))
	s.httpSrv = srv.Config
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("expected SSE content type, got %q", resp.Header.Get("Content-Type"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- s.Shutdown(ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown with active SSE client: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not return while SSE client was connected")
	}
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
