package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// sseWriteTimeout caps how long each SSE write is allowed to block on a
// slow or stuck client. It must stay below the daemon's WebUI shutdown
// budget so an in-flight flush cannot outlive graceful shutdown.
const sseWriteTimeout = 3 * time.Second

// apiEvents streams findings to the client over Server-Sent Events. A
// subscriber connects once and receives a `data: {...}\n\n` block per
// finding plus a periodic `: keepalive\n\n` comment line every 25s so
// intermediate proxies don't time the connection out. Auth is checked
// by the upstream requireRead middleware.
func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	bus := s.findingBus
	s.mu.RUnlock()

	if bus == nil {
		http.Error(w, "event bus not available", http.StatusServiceUnavailable)
		return
	}

	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Reserve a subscriber slot before sending any stream headers so a flood of
	// connections cannot exhaust daemon memory. Done up front so the cap can be
	// reported as a clean 503 rather than mid-stream.
	sub, ok := bus.TrySubscribe()
	if !ok {
		http.Error(w, "too many event stream subscribers", http.StatusServiceUnavailable)
		return
	}
	shutdownDone := s.pruneDone
	// The upstream middleware authenticates all subscribers. Only cookie
	// sessions have revocation/idle state to recheck during a stream.
	_, cookieErr := r.Cookie("csm_auth")
	cookieStream := cookieErr == nil && !s.isBearerAuth(r)
	streamStopped := func() bool {
		if r.Context().Err() != nil {
			return true
		}
		// Recheck session revocation/expiry before every event and heartbeat.
		// A passive stream must not keep an idle browser session alive.
		if cookieStream {
			if _, ok := s.cookieSessionToken(r, "read", false); !ok {
				return true
			}
		}
		select {
		case <-shutdownDone:
			return true
		default:
			return false
		}
	}
	defer func() {
		if streamStopped() {
			bus.Unsubscribe(sub)
		} else {
			bus.Abort(sub)
		}
	}()

	rc := http.NewResponseController(w)
	setWriteDeadline := func() error {
		return rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
	}
	if err := setWriteDeadline(); err != nil {
		http.Error(w, "streaming write deadlines unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx won't buffer

	writeFrame := func(format string, args ...any) error {
		if err := setWriteDeadline(); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return err
		}
		return rc.Flush()
	}

	// Initial flush establishes the connection and proxies see the headers
	// before the first event. Bound it by the same write deadline.
	if err := writeFrame(""); err != nil {
		return
	}

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	for {
		if streamStopped() {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-shutdownDone:
			return
		case <-keepalive.C:
			if streamStopped() {
				return
			}
			if err := writeFrame(": keepalive\n\n"); err != nil {
				return
			}
		case delivery, ok := <-sub.Events():
			if !ok {
				return
			}
			encodingFailed := false
			err := delivery.Process(func(f alert.Finding) error {
				if streamStopped() {
					return nil
				}
				body, err := json.Marshal(f)
				if err != nil {
					encodingFailed = true
					return err
				}
				err = writeFrame("data: %s\n\n", body)
				// Closing a tab can interrupt its write. Once demand is withdrawn,
				// that cancellation must not become a host delivery failure.
				if err != nil && streamStopped() {
					return nil
				}
				return err
			})
			if err != nil && !encodingFailed {
				return
			}
		}
	}
}
