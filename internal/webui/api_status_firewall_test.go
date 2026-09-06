package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/health"
)

func TestAPIStatusReportsUnmanagedFirewall(t *testing.T) {
	s := &Server{cfg: capsTestCfg()}
	s.SetHealthProvider(statusFakeProvider{automation: health.AutomationStatus{FirewallEnabled: true, FirewallStartupError: "fixture apply failure"}})
	rec := httptest.NewRecorder()
	s.apiStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	var got struct {
		Status     string
		Automation health.AutomationStatus
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || got.Status != "degraded" || got.Automation.FirewallManaged || got.Automation.FirewallStartupError != "fixture apply failure" {
		t.Fatalf("HTTP health hid firewall failure: %s", rec.Body.String())
	}
}
