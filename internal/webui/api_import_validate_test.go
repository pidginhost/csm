package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

// Imported whitelist entries must be validated like every interactive route:
// a malformed or non-routable address must not be added to the threat-DB
// allow-list (whitelisting bypasses blocking), while a valid public IP is
// stored in canonical form.
func TestAPIImportValidatesWhitelistIPs(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))

	body := `{"whitelist":[
		{"ip":"not-an-ip"},
		{"ip":"10.0.0.5"},
		{"ip":"203.0.113.7"}
	]}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiImport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	wl := checks.GetThreatDB().WhitelistedIPs()
	got := map[string]bool{}
	for _, e := range wl {
		got[e.IP] = true
	}
	if !got["203.0.113.7"] {
		t.Errorf("valid public IP should be whitelisted, got %v", wl)
	}
	if got["not-an-ip"] {
		t.Error("malformed IP must not be whitelisted")
	}
	if got["10.0.0.5"] {
		t.Error("private IP must not be whitelisted")
	}
}

// An exported bundle imports as it is. Import refused its own export because
// the strict decoder did not know the export's bookkeeping fields.
func TestAPIImportAcceptsItsOwnExport(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	checks.GetThreatDB().AddWhitelist("203.0.113.8")
	checks.GetThreatDB().TempWhitelist("203.0.113.9", time.Hour)

	exp := httptest.NewRecorder()
	s.apiExport(exp, httptest.NewRequest("GET", "/api/v1/export", nil))
	if exp.Code != http.StatusOK {
		t.Fatalf("export status = %d", exp.Code)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(exp.Body.String()))
	req.Header.Set("Content-Type", "application/json")
	s.apiImport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("import of an export: status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["ok"] != true {
		t.Errorf("ok = %v; body %s", resp["ok"], w.Body.String())
	}
}

// A temporary whitelist entry stays temporary on import, and an expired one
// is skipped rather than whitelisted for good.
func TestAPIImportKeepsWhitelistExpiry(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	future := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	body := `{"exported_at":"2026-09-23T10:00:00Z","hostname":"host.example","whitelist":[
		{"ip":"203.0.113.10","permanent":false,"expires_at":"` + future + `"},
		{"ip":"203.0.113.11","permanent":false,"expires_at":"` + past + `"},
		{"ip":"203.0.113.12","permanent":true}
	]}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiImport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	got := map[string]checks.WhitelistIP{}
	for _, e := range checks.GetThreatDB().WhitelistedIPs() {
		got[e.IP] = e
	}
	if e, ok := got["203.0.113.10"]; !ok || e.Permanent || e.ExpiresAt == nil {
		t.Errorf("temporary entry imported as %+v, want temporary", e)
	}
	if _, ok := got["203.0.113.11"]; ok {
		t.Error("an expired entry was whitelisted")
	}
	if e, ok := got["203.0.113.12"]; !ok || !e.Permanent {
		t.Errorf("permanent entry imported as %+v", e)
	}
	var resp struct {
		Imported int `json:"imported"`
		Skipped  int `json:"skipped"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Imported != 2 || resp.Skipped != 1 {
		t.Errorf("imported/skipped = %d/%d, want 2/1; body %s", resp.Imported, resp.Skipped, w.Body.String())
	}
}
