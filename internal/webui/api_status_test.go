package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/incident"
)

type statusFakeProvider struct {
	started              time.Time
	bpfEnforcementActive bool
	latestScan           time.Time
	baselineAt           time.Time
	automation           health.AutomationStatus
	update               health.UpdateInfo
	watchers             map[string]bool
	storeHealthy         *bool
}

func (statusFakeProvider) Hostname() string { return "h" }
func (f statusFakeProvider) StartedAt() time.Time {
	if !f.started.IsZero() {
		return f.started
	}
	return time.Now().Add(-time.Hour)
}
func (f statusFakeProvider) LatestScan() time.Time { return f.latestScan }
func (f statusFakeProvider) BaselineAt() time.Time { return f.baselineAt }
func (f statusFakeProvider) WatcherStatuses() map[string]bool {
	if f.watchers != nil {
		return f.watchers
	}
	return map[string]bool{"fanotify": true}
}
func (f statusFakeProvider) StoreHealthy() bool {
	if f.storeHealthy != nil {
		return *f.storeHealthy
	}
	return true
}
func (statusFakeProvider) StoreSizeMB() float64           { return 1.5 }
func (statusFakeProvider) SeverityCounts() map[string]int { return map[string]int{"high": 2} }
func (statusFakeProvider) BlocklistSize() int             { return 9 }
func (statusFakeProvider) IncidentsOpen() int             { return 2 }
func (f statusFakeProvider) BPFEnforcementActive() bool   { return f.bpfEnforcementActive }
func (statusFakeProvider) HistoryCount() int              { return 100 }
func (statusFakeProvider) ConfigHash() string             { return "cfg" }
func (statusFakeProvider) BinaryHash() string             { return "bin" }
func (statusFakeProvider) DryRunBlocksCount() int         { return 3 }
func (f statusFakeProvider) AutomationStatus() health.AutomationStatus {
	if f.automation == (health.AutomationStatus{}) {
		return health.AutomationStatus{AutoResponseDryRun: true, DryRunBlocks: 3}
	}
	return f.automation
}
func (f statusFakeProvider) UpdateInfo() health.UpdateInfo { return f.update }

var _ health.Provider = statusFakeProvider{}

func boolPtr(v bool) *bool { return &v }

func TestApiStatus_FullSnapshot(t *testing.T) {
	s := &Server{cfg: capsTestCfg(), startTime: time.Now().Add(-1 * time.Hour)}
	started := time.Date(2026, 5, 8, 11, 0, 0, 123, time.UTC)
	checkedAt := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	s.SetHealthProvider(statusFakeProvider{
		started:              started,
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
	if got["started_at_token"] != daemonStartToken(started) {
		t.Fatalf("expected started_at_token %q, got %v", daemonStartToken(started), got["started_at_token"])
	}
	automation, ok := got["automation"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected automation field present, got %T", got["automation"])
	}
	if automation["auto_response_dry_run"] != true || automation["dry_run_blocks"].(float64) != 3 {
		t.Fatalf("unexpected automation payload: %#v", automation)
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

func TestSecurityPosture(t *testing.T) {
	cases := []struct {
		name                           string
		opProblems, openCrit, openHigh int
		want                           string
	}{
		{"all clear", 0, 0, 0, "healthy"},
		{"active critical", 0, 1, 0, "critical"},
		{"active high", 0, 0, 1, "warning"},
		{"one op problem", 1, 0, 0, "warning"},
		{"two op problems", 2, 0, 0, "critical"},
		{"critical dominates high", 0, 1, 3, "critical"},
		{"one op problem plus open high", 1, 0, 2, "warning"},
		{"critical beats single op problem", 1, 1, 0, "critical"},
	}
	for _, tc := range cases {
		if got := securityPosture(tc.opProblems, tc.openCrit, tc.openHigh); got != tc.want {
			t.Errorf("%s: securityPosture(%d,%d,%d)=%q want %q",
				tc.name, tc.opProblems, tc.openCrit, tc.openHigh, got, tc.want)
		}
	}
}

func TestApiStatus_SecurityPostureWarnsOnDegradedSnapshot(t *testing.T) {
	cases := []struct {
		name     string
		provider statusFakeProvider
	}{
		{
			name: "detached watcher",
			provider: statusFakeProvider{
				watchers: map[string]bool{"fanotify": false, "maillog": true},
			},
		},
		{
			name: "unhealthy store",
			provider: statusFakeProvider{
				storeHealthy: boolPtr(false),
			},
		},
	}

	for _, tc := range cases {
		s := &Server{cfg: capsTestCfg(), startTime: time.Now().Add(-time.Hour)}
		s.SetHealthProvider(tc.provider)
		s.sigCount = 5

		rec := httptest.NewRecorder()
		s.apiStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))

		var got map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got["status"] != "degraded" {
			t.Fatalf("%s: status: want degraded, got %v", tc.name, got["status"])
		}
		if got["security_posture"] != "warning" {
			t.Fatalf("%s: security_posture: want warning, got %v", tc.name, got["security_posture"])
		}
	}
}

func TestApiStatus_SecurityPostureCriticalFromOpenIncident(t *testing.T) {
	s := &Server{cfg: capsTestCfg(), startTime: time.Now().Add(-time.Hour)}
	s.SetHealthProvider(statusFakeProvider{})
	// Daemon operationally fine (rules + watchers present) so the posture is
	// driven purely by the open critical incident, not by an op problem.
	s.sigCount = 5
	s.logWatcherCount = 3
	corr := incident.NewCorrelator(incident.CorrelatorConfig{})
	if _, created, err := corr.OnFinding(alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.Critical,
		TenantID:  "alice",
		Timestamp: time.Now(),
	}); err != nil || !created {
		t.Fatalf("seed incident: created=%v err=%v", created, err)
	}
	s.incidentCorrelator = corr

	rec := httptest.NewRecorder()
	s.apiStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))

	var got map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["security_posture"] != "critical" {
		t.Fatalf("security_posture: want critical, got %v", got["security_posture"])
	}
	bySev, ok := got["incidents_open_by_severity"].(map[string]interface{})
	if !ok {
		t.Fatalf("incidents_open_by_severity missing or wrong type: %T", got["incidents_open_by_severity"])
	}
	if bySev["critical"].(float64) != 1 {
		t.Fatalf("incidents_open_by_severity[critical]: want 1, got %v", bySev["critical"])
	}
}

func TestApiStatus_SecurityPostureHealthyWhenClean(t *testing.T) {
	s := &Server{cfg: capsTestCfg(), startTime: time.Now().Add(-time.Hour)}
	s.SetHealthProvider(statusFakeProvider{})
	s.sigCount = 5
	s.logWatcherCount = 3
	// No incident correlator => no active incidents.

	rec := httptest.NewRecorder()
	s.apiStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))

	var got map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["security_posture"] != "healthy" {
		t.Fatalf("security_posture: want healthy, got %v", got["security_posture"])
	}
	if _, ok := got["incidents_open_by_severity"]; !ok {
		t.Fatal("incidents_open_by_severity field missing")
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
