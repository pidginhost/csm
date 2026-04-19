package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/state"
)

// seedTestMetricOnce registers a deterministic counter in the process-
// default registry so /metrics has something to return. Tests in this
// package run in the same binary so the init happens once; subsequent
// tests see the same counter.
var seedTestMetricOnce sync.Once

func seedTestMetric() {
	seedTestMetricOnce.Do(func() {
		c := metrics.NewCounter("csm_webui_metrics_test_seed", "test seed counter")
		c.Inc()
		metrics.MustRegister("csm_webui_metrics_test_seed", c)
	})
}

func newMetricsTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s, err := New(cfg, st)
	if err != nil {
		t.Fatalf("webui.New: %v", err)
	}
	return s
}

func TestMetricsRejectsUnauthenticated(t *testing.T) {
	seedTestMetric()
	cfg := &config.Config{}
	cfg.WebUI.AuthToken = "ui-token"
	s := newMetricsTestServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	s.handleMetrics(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no-auth: got %d want 401", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("WWW-Authenticate header missing or malformed: %q", got)
	}
}

func TestMetricsAcceptsDedicatedToken(t *testing.T) {
	seedTestMetric()
	cfg := &config.Config{}
	cfg.WebUI.AuthToken = "ui-token"
	cfg.WebUI.MetricsToken = "scrape-token"
	s := newMetricsTestServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer scrape-token")
	rr := httptest.NewRecorder()
	s.handleMetrics(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("metrics-token: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type: got %q want text/plain...", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "# EOF") {
		t.Errorf("body missing # EOF:\n%s", body)
	}
	if !strings.Contains(body, "csm_webui_metrics_test_seed") {
		t.Errorf("body missing seed metric:\n%s", body)
	}
}

func TestMetricsRejectsWrongMetricsToken(t *testing.T) {
	seedTestMetric()
	cfg := &config.Config{}
	cfg.WebUI.AuthToken = "ui-token"
	cfg.WebUI.MetricsToken = "correct"
	s := newMetricsTestServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rr := httptest.NewRecorder()
	s.handleMetrics(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong-token: got %d want 401", rr.Code)
	}
}

func TestMetricsAcceptsUIAuthTokenAsFallback(t *testing.T) {
	seedTestMetric()
	cfg := &config.Config{}
	cfg.WebUI.AuthToken = "ui-token"
	// MetricsToken deliberately empty: the UI AuthToken should work.
	s := newMetricsTestServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer ui-token")
	rr := httptest.NewRecorder()
	s.handleMetrics(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("ui-token fallback: got %d want 200", rr.Code)
	}
}

func TestMetricsHEADHasNoBody(t *testing.T) {
	seedTestMetric()
	cfg := &config.Config{}
	cfg.WebUI.AuthToken = "ui-token"
	s := newMetricsTestServer(t, cfg)

	req := httptest.NewRequest(http.MethodHead, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer ui-token")
	rr := httptest.NewRecorder()
	s.handleMetrics(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("HEAD: got %d want 200", rr.Code)
	}
	if b, _ := io.ReadAll(rr.Body); len(b) != 0 {
		t.Errorf("HEAD body should be empty, got %d bytes", len(b))
	}
}

// TestMetricsTokenHotReload confirms that rotating
// webui.metrics_token via config.SetActive takes effect on the next
// request without restarting the webui server. This is the
// field-level hot-reload for WebUI.MetricsToken: its parent is
// restart-required but the token itself is tagged `hotreload:"safe"`
// and the handler reads config.Active() per request.
func TestMetricsTokenHotReload(t *testing.T) {
	seedTestMetric()
	cfg := &config.Config{}
	cfg.WebUI.AuthToken = "ui-token"
	cfg.WebUI.MetricsToken = "first"
	s := newMetricsTestServer(t, cfg)

	// Baseline: the startup token unlocks /metrics.
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer first")
	rr := httptest.NewRecorder()
	s.handleMetrics(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("baseline: got %d want 200", rr.Code)
	}

	// Simulate SIGHUP reload: swap to a new cfg with rotated token.
	rotated := *cfg
	rotated.WebUI.MetricsToken = "second"
	config.SetActive(&rotated)
	t.Cleanup(func() { config.SetActive(nil) })

	// The new token must work.
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer second")
	rr = httptest.NewRecorder()
	s.handleMetrics(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("rotated token: got %d want 200", rr.Code)
	}

	// The old token must NOT work anymore.
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer first")
	rr = httptest.NewRecorder()
	s.handleMetrics(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("pre-rotation token: got %d want 401 after rotation", rr.Code)
	}
}

func TestMetricsRejectsMethodPOST(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebUI.AuthToken = "ui-token"
	s := newMetricsTestServer(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer ui-token")
	rr := httptest.NewRecorder()
	s.handleMetrics(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: got %d want 405", rr.Code)
	}
}
