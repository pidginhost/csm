package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

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
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	flusher.Flush()

	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case f, ok := <-sub:
			if !ok {
				return
			}
			body, err := json.Marshal(f)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", body)
			flusher.Flush()
		}
	}
}
