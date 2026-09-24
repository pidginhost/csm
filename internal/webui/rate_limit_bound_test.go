package webui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

// At the ceiling every new address scanned the whole map under the global
// lock, so a flood of fresh addresses cost O(map size) per request. A sweep
// now makes room for many inserts at once, and evicts the oldest first.
func TestRateLimitMapSweepsRarelyAtTheCeiling(t *testing.T) {
	m := map[string][]time.Time{}
	base := time.Now()
	for i := 0; i < apiRateLimitMaxIPs; i++ {
		m[fmt.Sprintf("old-%d", i)] = []time.Time{base.Add(time.Duration(i) * time.Millisecond)}
	}
	start := rateLimitSweeps.Load()
	for i := 0; i < 200; i++ {
		boundRateLimitMap(m, base.Add(-time.Minute))
		m[fmt.Sprintf("new-%d", i)] = []time.Time{base.Add(time.Hour)}
	}
	if sweeps := rateLimitSweeps.Load() - start; sweeps > 1 {
		t.Fatalf("%d sweeps for 200 new addresses, want at most 1", sweeps)
	}
	if len(m) > apiRateLimitMaxIPs {
		t.Fatalf("map holds %d, ceiling %d", len(m), apiRateLimitMaxIPs)
	}
	if _, ok := m["old-0"]; ok {
		t.Fatal("the oldest address was kept while newer ones were evicted")
	}
	if _, ok := m[fmt.Sprintf("old-%d", apiRateLimitMaxIPs-1)]; !ok {
		t.Fatal("the newest old address was evicted before older ones")
	}
}
