package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/state"
)

func newSettingsTestServer(t *testing.T, token, yamlBody string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.StatePath = dir
	cfg.WebUI.AuthToken = token
	cfg.WebUI.UIDir = filepath.Join(dir, "ui-missing")
	if err := integrity.SignAndSaveAtomic(cfg, "sha256:testbinary"); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.StatePath = dir
	cfg.WebUI.AuthToken = token
	cfg.WebUI.UIDir = filepath.Join(dir, "ui-missing")

	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(nil) })

	config.SetActive(cfg)

	s, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	return s, cfgPath
}

func settingsAuthedReq(method, path, token, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestSettingsGETReturnsRedactedBodyAndETag(t *testing.T) {
	body := `hostname: t.example.com
reputation:
  abuseipdb_key: "secret-key-value"
  whitelist:
    - 10.0.0.1
`
	s, _ := newSettingsTestServer(t, "tok", body)

	req := settingsAuthedReq("GET", "/api/v1/settings/reputation", "tok", "")
	w := httptest.NewRecorder()
	s.apiSettingsGet(w, req)

	if w.Code != 200 {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
	if w.Header().Get("ETag") == "" {
		t.Error("missing ETag header")
	}

	var resp struct {
		Section        SettingsSection        `json:"section"`
		Values         map[string]interface{} `json:"values"`
		PendingRestart bool                   `json:"pending_restart"`
		PendingFields  []string               `json:"pending_fields"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Section.ID != "reputation" {
		t.Errorf("section.id = %q", resp.Section.ID)
	}
	if got := resp.Values["abuseipdb_key"]; got != "***REDACTED***" {
		t.Errorf("abuseipdb_key not redacted: %v", got)
	}
}

func TestSettingsGETUnknownSection404(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", "hostname: t\n")
	req := settingsAuthedReq("GET", "/api/v1/settings/nonexistent", "tok", "")
	w := httptest.NewRecorder()
	s.apiSettingsGet(w, req)
	if w.Code != 404 {
		t.Errorf("code = %d, want 404", w.Code)
	}
}

func TestSettingsGETRequiresAuth(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", "hostname: t\n")
	req := httptest.NewRequest("GET", "/api/v1/settings/alerts", nil)
	w := httptest.NewRecorder()
	s.requireAuth(http.HandlerFunc(s.apiSettingsGet)).ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

func TestSettingsGETNullableFieldPreservesRawNullState(t *testing.T) {
	body := `hostname: t.example.com
performance:
  enabled: null
  php_process_warn_per_user: 20
`
	s, _ := newSettingsTestServer(t, "tok", body)

	req := settingsAuthedReq("GET", "/api/v1/settings/performance", "tok", "")
	w := httptest.NewRecorder()
	s.apiSettingsGet(w, req)

	if w.Code != 200 {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Values map[string]interface{} `json:"values"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v, ok := resp.Values["enabled"]; !ok || v != nil {
		t.Errorf("values.enabled = %#v, want raw null for tri-state field", v)
	}
}
