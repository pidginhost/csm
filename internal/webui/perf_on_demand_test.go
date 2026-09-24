package webui

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Host metrics are sampled when the Performance page asks for them, at most
// once per perfSampleTTL, instead of every 10 seconds for the life of the
// daemon whether or not anyone looks.
func TestPerformanceMetricsAreSampledOnDemand(t *testing.T) {
	s := newTestServer(t, "tok")
	var samples atomic.Int32
	s.samplePerf = func() *perfMetrics {
		samples.Add(1)
		return &perfMetrics{CPUCores: 3}
	}
	get := func() {
		w := httptest.NewRecorder()
		s.apiPerformance(w, httptest.NewRequest(http.MethodGet, "/api/v1/performance", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("status %d", w.Code)
		}
	}

	if got := samples.Load(); got != 0 {
		t.Fatalf("sampled %d times before any request", got)
	}
	get()
	get()
	if got := samples.Load(); got != 1 {
		t.Fatalf("two requests inside the TTL sampled %d times, want 1", got)
	}

	old := perfSampleTTL
	perfSampleTTL = 0
	t.Cleanup(func() { perfSampleTTL = old })
	get()
	if got := samples.Load(); got != 2 {
		t.Fatalf("a request after the TTL sampled %d times in total, want 2", got)
	}
}

// Concurrent requests for stale metrics share one sample.
func TestPerformanceConcurrentRequestsShareOneSample(t *testing.T) {
	s := newTestServer(t, "tok")
	var samples atomic.Int32
	release := make(chan struct{})
	s.samplePerf = func() *perfMetrics {
		samples.Add(1)
		<-release
		return &perfMetrics{}
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.currentPerfMetrics()
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if got := samples.Load(); got != 1 {
		t.Fatalf("8 concurrent requests sampled %d times, want 1", got)
	}
}
