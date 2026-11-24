package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

func TestHardeningSavedReportGetsCurrentCautions(t *testing.T) {
	s := newTestServer(t, "tok")
	db := withTempStoreForWebui(t)
	report := &store.AuditReport{Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), ServerType: "cpanel", Score: 1, Total: 8,
		Results: []store.AuditResult{
			{Name: "ssh_max_auth_tries", Status: "warn", AutoFix: "Set MaxAuthTries"},
			{Name: "os_sysctl_rp_filter", Status: "warn", AutoFix: "Set rp_filter"},
			{Name: "cp_max_emails_hour", Status: "fail", AutoFix: "Limit mail"},
			{Name: "cp_nobodyspam", Status: "fail", AutoFix: "Block nobody mail"},
			{Name: "cp_cookie_validation", Status: "fail", AutoFix: "Strict cookies"},
			{Name: "ssh_use_dns", Status: "warn", AutoFix: "Disable DNS"},
			{Name: "ssh_max_auth_tries", Status: "pass"},
			{Name: "cp_nobodyspam", Status: "fail"},
		},
	}
	if err := db.SaveHardeningReport(report); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.apiHardening(rec, httptest.NewRequest(http.MethodGet, "/api/v1/hardening", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var got store.AuditReport
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != len(report.Results) {
		t.Fatalf("results: %+v", got.Results)
	}
	for i := range got.Results {
		if (got.Results[i].AutoFixCaution != "") != (i < 5) {
			t.Errorf("unexpected caution: %+v", got.Results[i])
		}
		got.Results[i].AutoFixCaution = ""
	}
	if !reflect.DeepEqual(got, *report) {
		t.Errorf("saved audit fields changed: %+v", got)
	}
	stored, err := db.LoadHardeningReport()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored, report) {
		t.Error("GET rewrote the saved report")
	}
}
