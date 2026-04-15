package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// apiGeoIPLookup:
//   - missing ip param → 400
//   - invalid IP format → 400
//   - GeoIP DB not loaded (default) → 503
//   (the happy path needs a real geoip.DB, which is out of scope here
//   — a unit test wrapping a MaxMind mmdb fixture would belong in the
//   geoip package, not here.)

func TestApiGeoIPLookupMissingIPReturns400(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.apiGeoIPLookup(w, httptest.NewRequest(http.MethodGet, "/api/v1/geoip", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestApiGeoIPLookupInvalidIPReturns400(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.apiGeoIPLookup(w, httptest.NewRequest(http.MethodGet, "/api/v1/geoip?ip=not-an-ip", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid ip, got %d", w.Code)
	}
}

func TestApiGeoIPLookupDBMissingReturns503(t *testing.T) {
	s := &Server{} // geoIPDB never set → Load() returns nil
	w := httptest.NewRecorder()
	s.apiGeoIPLookup(w, httptest.NewRequest(http.MethodGet, "/api/v1/geoip?ip=1.2.3.4", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when DB not loaded, got %d", w.Code)
	}
}

// apiGeoIPBatch:
//   - GET method → 405
//   - invalid JSON → 400
//   - over 500 IPs → 400
//   - DB missing → each result carries "GeoIP database not loaded"
//   - invalid format in one IP → that IP's result carries "invalid IP format"

func TestApiGeoIPBatchRejectsGET(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.apiGeoIPBatch(w, httptest.NewRequest(http.MethodGet, "/api/v1/geoip/batch", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestApiGeoIPBatchInvalidJSONReturns400(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/geoip/batch", strings.NewReader("{bad"))
	r.Header.Set("Content-Type", "application/json")
	s.apiGeoIPBatch(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed body, got %d", w.Code)
	}
}

func TestApiGeoIPBatchOverLimitReturns400(t *testing.T) {
	ips := make([]string, 501)
	for i := range ips {
		ips[i] = "1.1.1.1"
	}
	body, _ := json.Marshal(map[string]interface{}{"ips": ips})
	s := &Server{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/geoip/batch", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	s.apiGeoIPBatch(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for >500 ips, got %d", w.Code)
	}
}

func TestApiGeoIPBatchReportsPerIPErrors(t *testing.T) {
	body, _ := json.Marshal(map[string]interface{}{
		"ips": []string{"8.8.8.8", "not-an-ip", "1.2.3.4"},
	})
	s := &Server{} // no GeoIP DB
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/geoip/batch", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	s.apiGeoIPBatch(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (batch endpoint reports per-IP errors), got %d", w.Code)
	}
	var resp struct {
		Results map[string]struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !strings.Contains(resp.Results["not-an-ip"].Error, "invalid IP") {
		t.Errorf("invalid IP should report 'invalid IP format', got %q", resp.Results["not-an-ip"].Error)
	}
	if !strings.Contains(resp.Results["8.8.8.8"].Error, "GeoIP database not loaded") {
		t.Errorf("missing DB should surface in error field, got %q", resp.Results["8.8.8.8"].Error)
	}
}
