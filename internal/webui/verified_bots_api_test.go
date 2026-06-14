package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func vbotsGet(t *testing.T, s *Server, token string) (string, []map[string]any) {
	t.Helper()
	req := settingsAuthedReq("GET", "/api/v1/verified-bots", token, "")
	w := httptest.NewRecorder()
	s.apiVerifiedBots(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET code=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Bots []map[string]any `json:"bots"`
		Etag string           `json:"etag"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Etag, resp.Bots
}

func TestVerifiedBots_GetReturnsListAndEtag(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", "hostname: t.example.com\nreputation:\n  verified_bots: []\n")
	etag, bots := vbotsGet(t, s, "tok")
	if etag == "" {
		t.Error("expected a non-empty etag")
	}
	if len(bots) != 0 {
		t.Errorf("expected empty list, got %d", len(bots))
	}
}

func TestVerifiedBots_SaveValidPersistsAndReloads(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", "hostname: t.example.com\nreputation:\n  verified_bots: []\n")
	var reloaded bool
	s.SetVerifiedBotsReloader(func() error { reloaded = true; return nil })

	etag, _ := vbotsGet(t, s, "tok")
	body := `{"bots":[{"name":"perplexitybot","ua_substrings":["perplexitybot"],"ip_ranges":["18.97.9.96/29"]}]}`
	req := settingsAuthedReq("POST", "/api/v1/verified-bots/apply", "tok", body)
	req.Header.Set("If-Match", etag)
	w := httptest.NewRecorder()
	s.apiVerifiedBotsApply(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("save code=%d body=%s", w.Code, w.Body.String())
	}
	if !reloaded {
		t.Error("save did not invoke the live reloader")
	}
	_, bots := vbotsGet(t, s, "tok")
	if len(bots) != 1 || bots[0]["name"] != "perplexitybot" {
		t.Fatalf("persisted list = %+v", bots)
	}
	ranges, _ := bots[0]["ip_ranges"].([]any)
	if len(ranges) != 1 || ranges[0] != "18.97.9.96/29" {
		t.Fatalf("ip_ranges not persisted as snake_case JSON: %+v", bots[0])
	}
}

func TestVerifiedBots_SaveInvalidReturns422(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", "hostname: t.example.com\nreputation:\n  verified_bots: []\n")
	etag, _ := vbotsGet(t, s, "tok")
	// shared-hosting rDNS suffix must be rejected, just like a config load.
	body := `{"bots":[{"name":"x","ua_substrings":["xbotcrawler"],"rdns_suffixes":["amazonaws.com"]}]}`
	req := settingsAuthedReq("POST", "/api/v1/verified-bots/apply", "tok", body)
	req.Header.Set("If-Match", etag)
	w := httptest.NewRecorder()
	s.apiVerifiedBotsApply(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Errors []fieldError `json:"errors"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Errors) == 0 {
		t.Error("422 response should carry field errors")
	}
}

func TestVerifiedBots_SaveStaleEtagReturns412(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", "hostname: t.example.com\nreputation:\n  verified_bots: []\n")
	body := `{"bots":[]}`
	req := settingsAuthedReq("POST", "/api/v1/verified-bots/apply", "tok", body)
	req.Header.Set("If-Match", "sha256:stalevalue")
	w := httptest.NewRecorder()
	s.apiVerifiedBotsApply(w, req)
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("want 412, got %d: %s", w.Code, w.Body.String())
	}
}
