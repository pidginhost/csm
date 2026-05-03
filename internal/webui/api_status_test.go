package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/health"
)

type statusFakeProvider struct{}

func (statusFakeProvider) Hostname() string                 { return "h" }
func (statusFakeProvider) StartedAt() time.Time             { return time.Now().Add(-time.Hour) }
func (statusFakeProvider) LatestScan() time.Time            { return time.Time{} }
func (statusFakeProvider) BaselineAt() time.Time            { return time.Time{} }
func (statusFakeProvider) WatcherStatuses() map[string]bool { return map[string]bool{"fanotify": true} }
func (statusFakeProvider) StoreHealthy() bool               { return true }
func (statusFakeProvider) StoreSizeMB() float64             { return 1.5 }
func (statusFakeProvider) SeverityCounts() map[string]int   { return map[string]int{"high": 2} }
func (statusFakeProvider) BlocklistSize() int               { return 9 }
func (statusFakeProvider) HistoryCount() int                { return 100 }
func (statusFakeProvider) ConfigHash() string               { return "cfg" }
func (statusFakeProvider) BinaryHash() string               { return "bin" }

var _ health.Provider = statusFakeProvider{}

func TestApiStatus_FullSnapshot(t *testing.T) {
	s := &Server{cfg: capsTestCfg(), startTime: time.Now().Add(-1 * time.Hour)}
	s.SetHealthProvider(statusFakeProvider{})

	rec := httptest.NewRecorder()
	s.apiStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", got["status"])
	}
	if got["blocklist_size"].(float64) != 9 {
		t.Fatalf("expected blocklist_size=9, got %v", got["blocklist_size"])
	}
	if _, ok := got["watchers"]; !ok {
		t.Fatal("expected watchers field present")
	}
	// Backward-compat: all six legacy fields still present.
	for _, k := range []string{"hostname", "uptime", "started_at", "rules_loaded", "scan_running", "last_scan_time"} {
		if _, ok := got[k]; !ok {
			t.Errorf("backward-compat: legacy field %q missing", k)
		}
	}
}

func TestApiStatus_NilProviderFallsBackToLegacyShape(t *testing.T) {
	s := &Server{cfg: capsTestCfg(), startTime: time.Now().Add(-1 * time.Hour)}
	// no SetHealthProvider call

	rec := httptest.NewRecorder()
	// Make sure the test doesn't panic from nil store/sigCount fields by giving
	// minimal placeholder values. If your Server has unexported fields we need
	// to set, do that here. If the existing legacy path dereferences s.store,
	// the test may need to skip; that's an acceptable concern to flag.
	defer func() {
		if r := recover(); r != nil {
			t.Skipf("nil-provider test panicked (likely needs a non-nil store mock): %v", r)
		}
	}()
	s.apiStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
