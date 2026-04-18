package webui

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"

	"github.com/pidginhost/csm/internal/metrics"
)

// handleMetrics serves Prometheus text exposition from the process
// default metrics registry. ROADMAP item 4.
//
// Auth policy:
//
//   - If cfg.WebUI.MetricsToken is set, a matching `Authorization:
//     Bearer` header unlocks the endpoint. Operators should use this
//     for Prometheus scrapers so rotating the UI AuthToken does not
//     break scraping.
//   - As a fallback, a valid UI session cookie or the UI AuthToken
//     Bearer is accepted so the dashboard can self-scrape without a
//     second credential.
//
// No CSRF required: metrics is read-only and idempotent.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isMetricsAuthenticated(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="csm-metrics"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	if err := metrics.WriteOpenMetrics(w); err != nil {
		// The response body is already partially written; there is no
		// meaningful HTTP status to flip. Drop a server log line.
		fmt.Fprintf(os.Stderr, "webui: metrics WriteOpenMetrics: %v\n", err)
	}
}

func (s *Server) isMetricsAuthenticated(r *http.Request) bool {
	if tok := s.cfg.WebUI.MetricsToken; tok != "" {
		if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
			if subtle.ConstantTimeCompare([]byte(auth[7:]), []byte(tok)) == 1 {
				return true
			}
		}
	}
	// Fall back to the UI session / AuthToken path so the dashboard
	// can scrape itself without a second credential.
	return s.isAuthenticated(r)
}
