package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// sseWriteTimeout caps how long each SSE write is allowed to block on a
// slow or stuck client. Previously the handler set an infinite write
// deadline, which blocked graceful daemon shutdown indefinitely whenever
// any client was attached: the goroutine sat in flusher.Flush() until
// the OS eventually noticed the socket was dead. With a finite timeout
// the next keepalive write fails fast, the handler returns, and
// http.Server.Shutdown can complete.
const sseWriteTimeout = 30 * time.Second

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

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx won't buffer

	rc := http.NewResponseController(w)
	writeFrame := func(format string, args ...any) error {
		if err := rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	// Initial flush establishes the connection and proxies see the headers
	// before the first event. Bound it by the same write deadline.
	if err := writeFrame(""); err != nil {
		return
	}

	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			if err := writeFrame(": keepalive\n\n"); err != nil {
				return
			}
		case f, ok := <-sub:
			if !ok {
				return
			}
			body, err := json.Marshal(f)
			if err != nil {
				continue
			}
			if err := writeFrame("data: %s\n\n", body); err != nil {
				return
			}
		}
	}
}
