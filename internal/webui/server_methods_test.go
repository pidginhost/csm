package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func TestSetEmailQuarantine(t *testing.T) {
	s := newTestServer(t, "tok")
	s.SetEmailQuarantine(nil) // should not panic
}

func TestSetEmailAVWatcherMode(t *testing.T) {
	s := newTestServer(t, "tok")
	s.SetEmailAVWatcherMode("milter")
	if s.emailAVMode() != "milter" {
		t.Errorf("got %q", s.emailAVMode())
	}
}

// TestSetVersion is in coverage_test.go.

func TestCsmConfigRendersForThePage(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	s.version = "2.2.2"

	raw := string(jsonForScript(s.csmConfig()))
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		t.Fatalf("page config is not valid JSON: %v\nraw: %q", err, raw)
	}
	if data["version"] != "2.2.2" {
		t.Errorf("version = %v", data["version"])
	}
	if data["firewall"] != true {
		t.Errorf("firewall = %v", data["firewall"])
	}
	// Only admin credentials open a page (TestHTMLPagesRequireAdminScope),
	// so the page is not told a scope to hide read-only nav items by.
	if _, ok := data["authScope"]; ok {
		t.Errorf("authScope = %v; no page renders for another scope", data["authScope"])
	}
}

func TestSetGeoIPDB(t *testing.T) {
	s := newTestServer(t, "tok")
	s.SetGeoIPDB(nil) // should not panic
	if s.geoIPDB.Load() != nil {
		t.Error("nil db should store nil")
	}
}

// TestCheckNameHTTPASNCrawlHasFriendlyLabel asserts that the csmConfig
// checkNames map contains a friendly display label for the http_asn_crawl
// detector so that the UI never shows the raw check key to operators.
func TestCheckNameHTTPASNCrawlHasFriendlyLabel(t *testing.T) {
	s := newTestServer(t, "tok")
	cfg := s.csmConfig()
	names, ok := cfg["checkNames"].(map[string]string)
	if !ok {
		t.Fatal("csmConfig checkNames is not map[string]string")
	}
	label, found := names["http_asn_crawl"]
	if !found || label == "" {
		t.Error("http_asn_crawl has no entry in checkNames; UI will show raw key")
	}
	if label == "http_asn_crawl" {
		t.Errorf("http_asn_crawl resolves to raw key, want friendly label")
	}
}

// GeoIP lookup tests (missing/invalid/no-DB) are in coverage_test.go.

func TestAPIGeoIPBatchGetIsRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiGeoIPBatch(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET batch = %d, want 405", w.Code)
	}
}

// auth_success is an attack type; its label comes with the attack types.
func TestAuthSuccessHasFriendlyLabel(t *testing.T) {
	names := newTestServer(t, "tok").csmConfig()["attackTypes"].(map[string]string)
	if got := names["auth_success"]; got != "Authenticated Activity" {
		t.Fatalf("auth_success label = %q", got)
	}
}

// Attack types and check names are separate vocabularies: the Web UI gets
// the attack-type labels from attackdb, and checkNames holds only checks.
func TestCSMConfigSeparatesAttackTypesFromChecks(t *testing.T) {
	cfg := newTestServer(t, "tok").csmConfig()
	types, ok := cfg["attackTypes"].(map[string]string)
	if !ok {
		t.Fatal("csmConfig has no attackTypes map")
	}
	if types["brute_force"] != "Brute Force" || types["reputation"] != "Known Malicious IP" {
		t.Errorf("attackTypes = %v", types)
	}
	names := cfg["checkNames"].(map[string]string)
	for _, onlyType := range []string{"waf_block", "brute_force", "phishing", "spam", "file_upload", "auth_success", "recon", "c2", "other"} {
		if _, found := names[onlyType]; found {
			t.Errorf("checkNames still labels the attack type %s", onlyType)
		}
	}
	for _, check := range []string{"webshell", "cpanel_login"} {
		if names[check] == "" {
			t.Errorf("check %s lost its label", check)
		}
	}
}
