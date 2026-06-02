package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
