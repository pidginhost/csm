package threatintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/metrics"
)

func TestRegisterUpstreamMetricsCountersSurviveSourceRebuild(t *testing.T) {
	resetUpstreamMetricsForTest()
	reg := metrics.NewRegistry()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip": r.URL.Query().Get("ip"), "score": 30,
		})
	}))
	defer srv.Close()

	src1 := NewUpstreamSource(UpstreamConfig{URL: srv.URL, Timeout: time.Second})
	RegisterUpstreamMetrics(reg, src1)
	if _, err := src1.Score(context.Background(), "198.51.100.1"); err != nil {
		t.Fatal(err)
	}

	src2 := NewUpstreamSource(UpstreamConfig{URL: srv.URL, Timeout: time.Second})
	RegisterUpstreamMetrics(reg, src2)
	if _, err := src2.Score(context.Background(), "198.51.100.2"); err != nil {
		t.Fatal(err)
	}

	out := scrapeUpstreamMetrics(t, reg)
	if got := metricSample(out, "csm_threatintel_cache_misses_total"); got != "2" {
		t.Fatalf("cache misses metric = %q, want 2\n%s", got, out)
	}
}

func TestRegisterUpstreamMetricsBreakerGaugeTracksLatestSource(t *testing.T) {
	resetUpstreamMetricsForTest()
	reg := metrics.NewRegistry()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	src1 := NewUpstreamSource(UpstreamConfig{URL: srv.URL, Timeout: time.Second})
	src1.breakerTrip = 1
	src1.breakerCooldown = time.Hour
	RegisterUpstreamMetrics(reg, src1)
	if _, err := src1.Score(context.Background(), "198.51.100.1"); err == nil {
		t.Fatal("expected upstream failure")
	}

	out := scrapeUpstreamMetrics(t, reg)
	if got := metricSample(out, "csm_threatintel_breaker_open"); got != "1" {
		t.Fatalf("breaker metric after failure = %q, want 1\n%s", got, out)
	}

	src2 := NewUpstreamSource(UpstreamConfig{URL: srv.URL, Timeout: time.Second})
	RegisterUpstreamMetrics(reg, src2)
	out = scrapeUpstreamMetrics(t, reg)
	if got := metricSample(out, "csm_threatintel_breaker_open"); got != "0" {
		t.Fatalf("breaker metric after source rebuild = %q, want 0\n%s", got, out)
	}
}

func TestClearUpstreamMetricsSourceResetsBreakerGauge(t *testing.T) {
	resetUpstreamMetricsForTest()
	reg := metrics.NewRegistry()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{URL: srv.URL, Timeout: time.Second})
	src.breakerTrip = 1
	src.breakerCooldown = time.Hour
	RegisterUpstreamMetrics(reg, src)
	if _, err := src.Score(context.Background(), "198.51.100.1"); err == nil {
		t.Fatal("expected upstream failure")
	}

	ClearUpstreamMetricsSource()
	out := scrapeUpstreamMetrics(t, reg)
	if got := metricSample(out, "csm_threatintel_breaker_open"); got != "0" {
		t.Fatalf("breaker metric after clearing source = %q, want 0\n%s", got, out)
	}
}

func TestRegisterUpstreamMetricsRegistersEveryRegistry(t *testing.T) {
	resetUpstreamMetricsForTest()
	src := NewUpstreamSource(UpstreamConfig{URL: "http://127.0.0.1:1", Timeout: time.Second})
	reg1 := metrics.NewRegistry()
	reg2 := metrics.NewRegistry()

	RegisterUpstreamMetrics(reg1, src)
	RegisterUpstreamMetrics(reg2, src)

	for name, reg := range map[string]*metrics.Registry{"first": reg1, "second": reg2} {
		out := scrapeUpstreamMetrics(t, reg)
		if got := metricSample(out, "csm_threatintel_cache_hits_total"); got == "" {
			t.Fatalf("%s registry missing upstream metrics:\n%s", name, out)
		}
	}
}

func scrapeUpstreamMetrics(t *testing.T, reg *metrics.Registry) string {
	t.Helper()
	var sb strings.Builder
	if err := reg.WriteOpenMetrics(&sb); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	return sb.String()
}

func metricSample(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, name+" ") {
			return strings.TrimSpace(strings.TrimPrefix(line, name))
		}
	}
	return ""
}
