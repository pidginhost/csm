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
	if s.emailAVWatcherMode != "milter" {
		t.Errorf("got %q", s.emailAVWatcherMode)
	}
}

// TestSetVersion is in coverage_test.go.

func TestCsmConfigJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	s.version = "2.2.2"

	raw := s.csmConfigJSON()
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		t.Fatalf("csmConfigJSON not valid JSON: %v\nraw: %q", err, raw)
	}
	if data["version"] != "2.2.2" {
		t.Errorf("version = %v", data["version"])
	}
	if data["firewall"] != true {
		t.Errorf("firewall = %v", data["firewall"])
	}
	if data["authScope"] != "admin" {
		t.Errorf("authScope = %v", data["authScope"])
	}
}

func TestBroadcastNoPanic(t *testing.T) {
	s := newTestServer(t, "tok")
	s.Broadcast(nil)
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
