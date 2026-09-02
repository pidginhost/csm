package webui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The unauthenticated per-IP API rate-limit map only shrank on a five-minute
// prune, so a scan from many addresses grew it without bound in between.
// Inserts now keep the map under a fixed ceiling.
func TestAPIRateLimitMapStaysBounded(t *testing.T) {
	s := newTestServer(t, "tok")
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := s.securityHeaders(inner)
	for i := 0; i < apiRateLimitMaxIPs+500; i++ {
		req := httptest.NewRequest("GET", "/api/v1/status", nil)
		req.RemoteAddr = fmt.Sprintf("198.18.%d.%d:4000", i/256, i%256)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	s.apiMu.Lock()
	n := len(s.apiRequests)
	s.apiMu.Unlock()
	if n > apiRateLimitMaxIPs {
		t.Fatalf("rate-limit map holds %d addresses, ceiling is %d", n, apiRateLimitMaxIPs)
	}
}
