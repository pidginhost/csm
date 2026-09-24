package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// /metrics takes a bearer token like the API, so guessing it is limited the
// same way: per client address, the API request budget.
func TestMetricsIsRateLimitedLikeTheAPI(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.WebUI.MetricsToken = "metrics-secret-token-value"
	var last int
	for i := 0; i < 601; i++ {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "203.0.113.9:40000"
		req.Header.Set("Authorization", "Bearer wrong-guess")
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("request 601 got %d, want 429", last)
	}
}
