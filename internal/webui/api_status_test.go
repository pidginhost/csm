package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/health"
)

type statusFakeProvider struct {
	bpfEnforcementActive bool
	update               health.UpdateInfo
}

func (statusFakeProvider) Hostname() string                 { return "h" }
func (statusFakeProvider) StartedAt() time.Time             { return time.Now().Add(-time.Hour) }
func (statusFakeProvider) LatestScan() time.Time            { return time.Time{} }
func (statusFakeProvider) BaselineAt() time.Time            { return time.Time{} }
func (statusFakeProvider) WatcherStatuses() map[string]bool { return map[string]bool{"fanotify": true} }
func (statusFakeProvider) StoreHealthy() bool               { return true }
func (statusFakeProvider) StoreSizeMB() float64             { return 1.5 }
func (statusFakeProvider) SeverityCounts() map[string]int   { return map[string]int{"high": 2} }
func (statusFakeProvider) BlocklistSize() int               { return 9 }
func (statusFakeProvider) IncidentsOpen() int               { return 2 }
func (f statusFakeProvider) BPFEnforcementActive() bool     { return f.bpfEnforcementActive }
func (statusFakeProvider) HistoryCount() int                { return 100 }
func (statusFakeProvider) ConfigHash() string               { return "cfg" }
func (statusFakeProvider) BinaryHash() string               { return "bin" }
func (statusFakeProvider) DryRunBlocksCount() int           { return 3 }
func (f statusFakeProvider) UpdateInfo() health.UpdateInfo  { return f.update }

var _ health.Provider = statusFakeProvider{}

func TestApiStatus_FullSnapshot(t *testing.T) {
	s := &Server{cfg: capsTestCfg(), startTime: time.Now().Add(-1 * time.Hour)}
	checkedAt := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	s.SetHealthProvider(statusFakeProvider{
		bpfEnforcementActive: true,
		update: health.UpdateInfo{
			LatestVersion: "3.0.1",
			Available:     true,
			Source:        "github",
			CheckedAt:     checkedAt,
		},
	})

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
	if got["incidents_open"].(float64) != 2 {
		t.Fatalf("expected incidents_open=2, got %v", got["incidents_open"])
	}
	if active, ok := got["bpf_enforcement_active"].(bool); !ok || !active {
		t.Fatalf("expected bpf_enforcement_active=true, got %v", got["bpf_enforcement_active"])
	}
	if _, ok := got["watchers"]; !ok {
		t.Fatal("expected watchers field present")
	}
	if got["dry_run_blocks"].(float64) != 3 {
		t.Fatalf("expected dry_run_blocks=3, got %v", got["dry_run_blocks"])
	}
	update, ok := got["update"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected update field present, got %T", got["update"])
	}
	if update["latest_version"] != "3.0.1" || update["available"] != true {
		t.Fatalf("unexpected update payload: %#v", update)
	}
	// Backward-compat: all six legacy fields still present.
	for _, k := range []string{"hostname", "uptime", "started_at", "rules_loaded", "scan_running", "last_scan_time"} {
		if _, ok := got[k]; !ok {
			t.Errorf("backward-compat: legacy field %q missing", k)
		}
	}
}

func TestApiStatus_OmitsZeroUpdate(t *testing.T) {
	s := &Server{cfg: capsTestCfg(), startTime: time.Now().Add(-1 * time.Hour)}
	s.SetHealthProvider(statusFakeProvider{})

	rec := httptest.NewRecorder()
	s.apiStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))

	var got map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["update"]; ok {
		t.Fatalf("expected update omitted before first poll, got %#v", got["update"])
	}
}

func TestApiStatus_NilProviderFallsBackToLegacyShape(t *testing.T) {
	s := &Server{cfg: capsTestCfg(), startTime: time.Now().Add(-1 * time.Hour)}
	// no SetHealthProvider call

	rec := httptest.NewRecorder()
	s.apiStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
