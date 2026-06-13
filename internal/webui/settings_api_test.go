package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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
	if serr := integrity.SignAndSaveAtomic(cfg, "sha256:testbinary"); serr != nil {
		t.Fatal(serr)
	}
	cfg, err = config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.StatePath = dir
	cfg.WebUI.AuthToken = token
	// Mirror applyDefaults: migrate legacy AuthToken into Tokens so that
	// scope-aware auth works in tests without a full config reload.
	cfg.WebUI.Tokens = []config.WebUIToken{{Name: "legacy-auth-token", Token: token, Scope: "admin"}}
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

func newSettingsTestServerWithConfDir(t *testing.T, token, yamlBody string, fragments map[string]string) (*Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")
	confDir := filepath.Join(dir, "conf.d")
	if err := os.WriteFile(cfgPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range fragments {
		if err := os.WriteFile(filepath.Join(confDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.LoadWithDir(cfgPath, confDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.StatePath = dir
	cfg.WebUI.AuthToken = token
	cfg.WebUI.UIDir = filepath.Join(dir, "ui-missing")
	if serr := integrity.SignAndSaveAtomic(cfg, "sha256:testbinary"); serr != nil {
		t.Fatal(serr)
	}
	cfg, err = config.LoadWithDir(cfgPath, confDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.StatePath = dir
	cfg.WebUI.AuthToken = token
	cfg.WebUI.Tokens = []config.WebUIToken{{Name: "legacy-auth-token", Token: token, Scope: "admin"}}
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
	return s, cfgPath, confDir
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

func TestSettingsSectionsGETReturnsBackendSchema(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", "hostname: t.example.com\n")

	req := settingsAuthedReq("GET", "/api/v1/settings", "tok", "")
	w := httptest.NewRecorder()
	s.apiSettingsSections(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
	var body struct {
		Groups   []string          `json:"groups"`
		Sections []SettingsSection `json:"sections"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(body.Groups) != len(SectionGroupOrder) {
		t.Fatalf("groups len = %d, want %d", len(body.Groups), len(SectionGroupOrder))
	}
	if len(body.Sections) != len(AllSettingsSections()) {
		t.Fatalf("sections len = %d, want %d", len(body.Sections), len(AllSettingsSections()))
	}
	if body.Sections[0].ID != "alerts" {
		t.Fatalf("first section = %q, want alerts", body.Sections[0].ID)
	}
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

func TestSettingsPOSTAppliesSafeFieldLive(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
auto_response:
  enabled: true
  block_ips: false
  http_scanner_action: "challenge"
  netblock_threshold: 3
  max_blocks_per_hour: 50
`
	s, cfgPath := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/auto_response", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag from GET")
	}

	postReq := settingsAuthedReq("POST", "/api/v1/settings/auto_response", "tok", `{"changes":{"block_ips":true,"http_scanner_action":"block","netblock_threshold":5,"max_blocks_per_hour":75}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("code = %d, body = %s", postW.Code, postW.Body.String())
	}
	var resp struct {
		RequiresRestart []string `json:"requires_restart"`
		PendingRestart  bool     `json:"pending_restart"`
		NewETag         string   `json:"new_etag"`
	}
	_ = json.Unmarshal(postW.Body.Bytes(), &resp)
	if resp.PendingRestart {
		t.Error("auto_response is safe; pending_restart should be false")
	}
	if resp.NewETag == "" || resp.NewETag == etag {
		t.Errorf("etag did not rotate: %q -> %q", etag, resp.NewETag)
	}
	live := config.Active()
	if !live.AutoResponse.BlockIPs {
		t.Error("live AutoResponse.BlockIPs not updated")
	}
	if live.AutoResponse.HTTPScannerAction != "block" {
		t.Errorf("HTTPScannerAction = %q, want block", live.AutoResponse.HTTPScannerAction)
	}
	if live.AutoResponse.NetBlockThreshold != 5 {
		t.Errorf("NetBlockThreshold = %d", live.AutoResponse.NetBlockThreshold)
	}
	if live.AutoResponse.MaxBlocksPerHour != 75 {
		t.Errorf("MaxBlocksPerHour = %d, want 75", live.AutoResponse.MaxBlocksPerHour)
	}
	loaded, _ := config.Load(cfgPath)
	if !loaded.AutoResponse.BlockIPs {
		t.Error("disk not updated")
	}
	if loaded.AutoResponse.HTTPScannerAction != "block" {
		t.Errorf("disk HTTPScannerAction = %q, want block", loaded.AutoResponse.HTTPScannerAction)
	}
	if loaded.AutoResponse.MaxBlocksPerHour != 75 {
		t.Errorf("disk MaxBlocksPerHour = %d, want 75", loaded.AutoResponse.MaxBlocksPerHour)
	}
	if loaded.Integrity.ConfigHash != resp.NewETag {
		t.Errorf("disk config_hash = %q, new_etag = %q", loaded.Integrity.ConfigHash, resp.NewETag)
	}
}

func TestSettingsPOSTRejectsUnknownHTTPScannerAction(t *testing.T) {
	body := `hostname: t.example.com
auto_response:
  enabled: true
  http_scanner_action: "challenge"
`
	s, cfgPath := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/auto_response", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/auto_response", "tok", `{"changes":{"http_scanner_action":"captcha"}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != http.StatusUnprocessableEntity {
		t.Fatalf("code = %d, want 422, body = %s", postW.Code, postW.Body.String())
	}
	var resp struct {
		Errors []struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(postW.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Errors) != 1 {
		t.Fatalf("errors = %+v, want one http_scanner_action error", resp.Errors)
	}
	if resp.Errors[0].Field != "http_scanner_action" || !strings.Contains(resp.Errors[0].Message, "captcha") {
		t.Fatalf("errors = %+v, want rejected scanner action value", resp.Errors)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AutoResponse.HTTPScannerAction != "challenge" {
		t.Fatalf("disk HTTPScannerAction = %q, want unchanged challenge", loaded.AutoResponse.HTTPScannerAction)
	}
}

func TestSettingsPOSTPreservesConfdHashWithFragments(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
auto_response:
  enabled: true
  block_ips: false
  netblock_threshold: 3
  max_blocks_per_hour: 50
`
	s, cfgPath, confDir := newSettingsTestServerWithConfDir(t, "tok", body, map[string]string{
		"10-thresholds.yaml": "thresholds:\n  mail_queue_warn: 150\n",
	})
	oldConfdHash := config.Active().Integrity.ConfdHash

	getReq := settingsAuthedReq("GET", "/api/v1/settings/auto_response", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag from GET")
	}

	postReq := settingsAuthedReq("POST", "/api/v1/settings/auto_response", "tok", `{"changes":{"block_ips":true}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)
	if postW.Code != 200 {
		t.Fatalf("code = %d, body = %s", postW.Code, postW.Body.String())
	}

	loaded, err := config.LoadWithDir(cfgPath, confDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Integrity.ConfdHash != oldConfdHash {
		t.Fatalf("disk confd_hash = %q, want %q", loaded.Integrity.ConfdHash, oldConfdHash)
	}
	live := config.Active()
	if live.Integrity.ConfdHash != loaded.Integrity.ConfdHash {
		t.Fatalf("live confd_hash = %q, disk = %q", live.Integrity.ConfdHash, loaded.Integrity.ConfdHash)
	}
	if live.ConfigDir != confDir {
		t.Fatalf("live ConfigDir = %q, want %q", live.ConfigDir, confDir)
	}
}

func TestSettingsPOSTRejectsStaleConfdHashAfterFragmentChange(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
auto_response:
  enabled: true
  block_ips: false
  netblock_threshold: 3
  max_blocks_per_hour: 50
`
	s, cfgPath, confDir := newSettingsTestServerWithConfDir(t, "tok", body, map[string]string{
		"10-thresholds.yaml": "thresholds:\n  mail_queue_warn: 150\n",
	})
	oldConfdHash := config.Active().Integrity.ConfdHash
	if err := os.WriteFile(filepath.Join(confDir, "10-thresholds.yaml"), []byte("thresholds:\n  mail_queue_warn: 175\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	getReq := settingsAuthedReq("GET", "/api/v1/settings/auto_response", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag from GET")
	}

	postReq := settingsAuthedReq("POST", "/api/v1/settings/auto_response", "tok", `{"changes":{"block_ips":true}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)
	if postW.Code != http.StatusPreconditionFailed {
		t.Fatalf("code = %d, want 412, body = %s", postW.Code, postW.Body.String())
	}

	loaded, err := config.LoadWithDir(cfgPath, confDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AutoResponse.BlockIPs {
		t.Fatal("disk config was updated despite stale conf.d hash")
	}
	if config.Active().Integrity.ConfdHash != oldConfdHash {
		t.Fatalf("live confd_hash changed despite rejected save")
	}
}

func TestSettingsPOSTRestartFieldSavesDiskKeepsLive(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
challenge:
  enabled: false
  listen_port: 8439
  difficulty: 2
`
	s, cfgPath := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/challenge", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/challenge", "tok", `{"changes":{"enabled":true,"difficulty":3}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("code = %d, body = %s", postW.Code, postW.Body.String())
	}
	var resp struct {
		RequiresRestart []string `json:"requires_restart"`
		PendingRestart  bool     `json:"pending_restart"`
		NewETag         string   `json:"new_etag"`
	}
	_ = json.Unmarshal(postW.Body.Bytes(), &resp)
	if !resp.PendingRestart {
		t.Error("challenge is restart-required; pending_restart should be true")
	}
	live := config.Active()
	if live.Challenge.Enabled {
		t.Error("live should not reflect restart-required change")
	}
	if live.Challenge.Difficulty != 2 {
		t.Errorf("live difficulty = %d, want 2 (unchanged)", live.Challenge.Difficulty)
	}
	if live.Integrity.ConfigHash != resp.NewETag {
		t.Errorf("live Integrity.ConfigHash = %q, want %q (new etag)", live.Integrity.ConfigHash, resp.NewETag)
	}
	loaded, _ := config.Load(cfgPath)
	if !loaded.Challenge.Enabled {
		t.Error("disk should have challenge.enabled=true")
	}
}

func TestSettingsPOSTIfMatchMismatch412(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 30
`
	s, _ := newSettingsTestServer(t, "tok", body)

	postReq := settingsAuthedReq("POST", "/api/v1/settings/alerts", "tok", `{"changes":{"max_per_hour":50}}`)
	postReq.Header.Set("If-Match", "sha256:stale")
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 412 {
		t.Errorf("code = %d, want 412", postW.Code)
	}
}

func TestSettingsPOSTMissingIfMatch400(t *testing.T) {
	body := `hostname: t
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
`
	s, _ := newSettingsTestServer(t, "tok", body)
	postReq := settingsAuthedReq("POST", "/api/v1/settings/alerts", "tok", `{"changes":{}}`)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)
	if postW.Code != 400 {
		t.Errorf("code = %d, want 400", postW.Code)
	}
}

func TestSettingsPOSTInvalidValue422(t *testing.T) {
	body := `hostname: t
alerts:
  email:
    enabled: true
    to: ["ops@example.com"]
    from: csm@example.com
    smtp: smtp.example.com:587
`
	s, _ := newSettingsTestServer(t, "tok", body)
	getReq := settingsAuthedReq("GET", "/api/v1/settings/alerts", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	// Remove the recipient list: email enabled + empty To is a Validate error.
	postReq := settingsAuthedReq("POST", "/api/v1/settings/alerts", "tok", `{"changes":{"email.to":[]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 422 {
		t.Errorf("code = %d, want 422, body = %s", postW.Code, postW.Body.String())
	}
	var resp struct {
		Errors []struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(postW.Body.Bytes(), &resp)
	if len(resp.Errors) == 0 {
		t.Errorf("expected field errors, body = %s", postW.Body.String())
	}
}

func TestSettingsPOSTRejectsVerdictCallbackWithoutSecret(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@example.com"]
    from: csm@example.com
    smtp: smtp.example.com:587
auto_response:
  enabled: true
`
	s, _ := newSettingsTestServer(t, "tok", body)
	getReq := settingsAuthedReq("GET", "/api/v1/settings/auto_response", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/auto_response", "tok", `{"changes":{"verdict_callback.enabled":true,"verdict_callback.url":"https://panel.example.com/api/csm/verdict"}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != http.StatusUnprocessableEntity {
		t.Fatalf("code = %d, want 422, body = %s", postW.Code, postW.Body.String())
	}
	var resp struct {
		Errors []struct {
			Field string `json:"field"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(postW.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, e := range resp.Errors {
		if e.Field == "auto_response.verdict_callback.hmac_secret" {
			return
		}
	}
	t.Fatalf("expected verdict callback HMAC error, got %s", postW.Body.String())
}

func TestSettingsPOSTNullForNonNullableField422(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
auto_response:
  enabled: true
  block_ips: false
`
	s, _ := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/auto_response", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/auto_response", "tok", `{"changes":{"block_ips":null}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 422 {
		t.Fatalf("code = %d, body = %s", postW.Code, postW.Body.String())
	}
}

func TestSettingsPOSTDeepValidationScopedToEditedSection(t *testing.T) {
	// alerts.email enabled with an SMTP pointing at a deliberately-dead address
	// would fail probeSMTP if we ran full ValidateDeep. Editing auto_response
	// must NOT surface that unrelated error.
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@example.com"]
    from: "csm@example.com"
    smtp: "127.0.0.1:1"
auto_response:
  enabled: true
  block_ips: false
`
	s, _ := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/auto_response", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/auto_response", "tok", `{"changes":{"block_ips":true}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("unrelated alerts deep validation should not block auto_response save: %d: %s", postW.Code, postW.Body.String())
	}
}

func TestSettingsPOSTRedactedSecretDropped(t *testing.T) {
	body := `hostname: t
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
reputation:
  abuseipdb_key: "live-key-value"
  whitelist:
    - 10.0.0.1
`
	s, cfgPath := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/reputation", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/reputation", "tok", `{"changes":{"abuseipdb_key":"***REDACTED***","whitelist":["10.0.0.2"]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("code = %d, body = %s", postW.Code, postW.Body.String())
	}
	loaded, _ := config.Load(cfgPath)
	if loaded.Reputation.AbuseIPDBKey != "live-key-value" {
		t.Errorf("secret was overwritten: %q", loaded.Reputation.AbuseIPDBKey)
	}
	if len(loaded.Reputation.Whitelist) != 1 || loaded.Reputation.Whitelist[0] != "10.0.0.2" {
		t.Errorf("whitelist not updated: %v", loaded.Reputation.Whitelist)
	}
}

func TestSettingsPOSTEmptyStringClearsSecret(t *testing.T) {
	body := `hostname: t
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
sentry:
  enabled: true
  dsn: "https://existing@example.com/1"
  environment: prod
  sample_rate: 1.0
`
	s, cfgPath := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/sentry", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/sentry", "tok", `{"changes":{"dsn":""}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("code = %d, body = %s", postW.Code, postW.Body.String())
	}
	loaded, _ := config.Load(cfgPath)
	if loaded.Sentry.DSN != "" {
		t.Errorf("dsn = %q, want empty", loaded.Sentry.DSN)
	}
}

func TestSettingsPOSTAuditRecordWrittenWithMaskedSecret(t *testing.T) {
	body := `hostname: t
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
reputation:
  abuseipdb_key: "old"
`
	s, _ := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/reputation", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/reputation", "tok", `{"changes":{"abuseipdb_key":"new-secret"}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("code = %d, body = %s", postW.Code, postW.Body.String())
	}
	entries := readUIAuditLog(s.cfg.StatePath, 10)
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	var found bool
	for _, e := range entries {
		if e.Action == "settings-save" {
			found = true
			if !strings.Contains(e.Details, "***") {
				t.Errorf("audit details do not mask secret: %q", e.Details)
			}
			if strings.Contains(e.Details, "new-secret") {
				t.Errorf("audit leaked secret value: %q", e.Details)
			}
			break
		}
	}
	if !found {
		t.Error("no settings-save audit entry")
	}
}

func TestSettingsRestartEndpointInvokesSystemctl(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", "hostname: t\nalerts:\n  email:\n    enabled: true\n    to: [\"ops@t.example.com\"]\n    from: csm@t.example.com\n    smtp: \"127.0.0.1:1\"\n  max_per_hour: 20\n")
	calls := 0
	s.restartDaemon = func() ([]byte, error) {
		calls++
		return []byte("ok"), nil
	}

	postReq := settingsAuthedReq("POST", "/api/v1/settings/restart", "tok", "")
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsRestart(postW, postReq)

	if postW.Code != 202 {
		t.Errorf("code = %d, want 202", postW.Code)
	}
	if calls != 1 {
		t.Errorf("restartDaemon called %d times, want 1", calls)
	}
}

func TestSettingsRestartEndpointSurfacesFailure(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", "hostname: t\nalerts:\n  email:\n    enabled: true\n    to: [\"ops@t.example.com\"]\n    from: csm@t.example.com\n    smtp: \"127.0.0.1:1\"\n  max_per_hour: 20\n")
	s.restartDaemon = func() ([]byte, error) {
		return []byte("Failed to restart csm.service: Unit not found."), fmt.Errorf("exit status 5")
	}

	postReq := settingsAuthedReq("POST", "/api/v1/settings/restart", "tok", "")
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsRestart(postW, postReq)

	if postW.Code != 500 {
		t.Errorf("code = %d, want 500", postW.Code)
	}
	if !strings.Contains(postW.Body.String(), "Unit not found") {
		t.Errorf("body missing stderr: %s", postW.Body.String())
	}
}

func TestSettingsPOSTDisabledChecksUpdates(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
disabled_checks: []
`
	s, cfgPath := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/disabled_checks", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	if getW.Code != 200 {
		t.Fatalf("GET code = %d, body = %s", getW.Code, getW.Body.String())
	}
	etag := getW.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}

	postReq := settingsAuthedReq("POST", "/api/v1/settings/disabled_checks", "tok", `{"changes":{"":["waf_status","waf_rules"]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("POST code = %d, body = %s", postW.Code, postW.Body.String())
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload after POST: %v", err)
	}
	if got := loaded.DisabledChecks; len(got) != 2 || got[0] != "waf_status" || got[1] != "waf_rules" {
		t.Errorf("DisabledChecks = %v, want [waf_status waf_rules]", got)
	}
}

// A typo in a top-level disabled_checks value must be rejected, not silently
// saved -- otherwise the operator believes a noisy check is disabled while it
// keeps running. The nested alerts email.disabled_checks enum already rejects
// unknown values; the scheduled-scan list must too.
func TestSettingsPOSTDisabledChecksRejectsUnknown(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
disabled_checks: []
`
	s, _ := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/disabled_checks", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/disabled_checks", "tok",
		`{"changes":{"":["waf_status","totally_bogus_check_xyz"]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 422 {
		t.Fatalf("POST code = %d, want 422, body = %s", postW.Code, postW.Body.String())
	}
	if !strings.Contains(postW.Body.String(), "totally_bogus_check_xyz") {
		t.Errorf("response should name the bad value, got %s", postW.Body.String())
	}
}

// Existing operator configs disable checks by runner ID (e.g. "php_content"),
// not just public finding names. Validation must accept those compatibility
// IDs so a save does not reject a config the scheduler already honors.
func TestSettingsPOSTDisabledChecksAcceptsLegacyRunnerID(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
disabled_checks: []
`
	s, cfgPath := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/disabled_checks", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/disabled_checks", "tok",
		`{"changes":{"":["php_content"]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("POST code = %d, want 200, body = %s", postW.Code, postW.Body.String())
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload after POST: %v", err)
	}
	if got := loaded.DisabledChecks; len(got) != 1 || got[0] != "php_content" {
		t.Errorf("DisabledChecks = %v, want [php_content]", got)
	}
}

func TestSettingsPOSTInfraIPsUpdates(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
infra_ips:
  - "10.0.0.1"
`
	s, cfgPath := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/infra_ips", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}

	// infra_ips schema field has YAMLPath "" -- the POST body uses "" as the key.
	postReq := settingsAuthedReq("POST", "/api/v1/settings/infra_ips", "tok", `{"changes":{"":["10.0.0.1","10.0.0.2","2001:db8::/64"]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("code = %d, body = %s", postW.Code, postW.Body.String())
	}
	loaded, _ := config.Load(cfgPath)
	if len(loaded.InfraIPs) != 3 {
		t.Errorf("InfraIPs length = %d, want 3; got %v", len(loaded.InfraIPs), loaded.InfraIPs)
	}
}

func TestSettingsPOSTFloatFieldRoundTrips(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
performance:
  enabled: true
  load_high_multiplier: 1.0
  load_critical_multiplier: 2.0
`
	s, cfgPath := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/performance", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	// Send as JSON number
	postReq := settingsAuthedReq("POST", "/api/v1/settings/performance", "tok", `{"changes":{"load_high_multiplier":1.75}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)
	if postW.Code != 200 {
		t.Fatalf("code = %d, body = %s", postW.Code, postW.Body.String())
	}
	loaded, _ := config.Load(cfgPath)
	if loaded.Performance.LoadHighMultiplier != 1.75 {
		t.Errorf("LoadHighMultiplier = %v, want 1.75", loaded.Performance.LoadHighMultiplier)
	}

	// And as JSON string (defensive handling)
	var resp struct {
		NewETag string `json:"new_etag"`
	}
	_ = json.Unmarshal(postW.Body.Bytes(), &resp)

	postReq2 := settingsAuthedReq("POST", "/api/v1/settings/performance", "tok", `{"changes":{"load_critical_multiplier":"3.25"}}`)
	postReq2.Header.Set("If-Match", resp.NewETag)
	postReq2.Header.Set("X-CSRF-Token", s.csrfToken())
	postW2 := httptest.NewRecorder()
	s.apiSettingsPost(postW2, postReq2)
	if postW2.Code != 200 {
		t.Fatalf("string-form code = %d, body = %s", postW2.Code, postW2.Body.String())
	}
	loaded2, _ := config.Load(cfgPath)
	if loaded2.Performance.LoadCriticalMultiplier != 3.25 {
		t.Errorf("LoadCriticalMultiplier = %v, want 3.25", loaded2.Performance.LoadCriticalMultiplier)
	}
}

func TestSettingsGETResolvesEnumArrayOptions(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
    disabled_checks: ["webshell"]
  max_per_hour: 20
`
	s, _ := newSettingsTestServer(t, "tok", body)

	req := settingsAuthedReq("GET", "/api/v1/settings/alerts", "tok", "")
	w := httptest.NewRecorder()
	s.apiSettingsGet(w, req)
	if w.Code != 200 {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Section SettingsSection `json:"section"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var f *SettingsField
	for i := range resp.Section.Fields {
		if resp.Section.Fields[i].YAMLPath == "email.disabled_checks" {
			f = &resp.Section.Fields[i]
		}
	}
	if f == nil {
		t.Fatal("email.disabled_checks field missing")
	}
	if f.Type != "[]enum" {
		t.Errorf("type = %q, want []enum", f.Type)
	}
	if len(f.Options) == 0 {
		t.Error("Options empty in GET response — resolveFieldOptions not wired")
	}
	if len(f.OptionGroups) == 0 {
		t.Error("OptionGroups empty in GET response")
	}
}

func TestSettingsPOSTRejectsUnknownEnumValue(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: false
    to: ["ops@t.example.com"]
    from: csm@t.example.com
  webhook:
    enabled: false
    type: "slack"
  max_per_hour: 20
`
	s, _ := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/alerts", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/alerts", "tok",
		`{"changes":{"email.disabled_checks":["webshell","nonexistent_check"]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 422 {
		t.Fatalf("code = %d, want 422, body = %s", postW.Code, postW.Body.String())
	}
	if !strings.Contains(postW.Body.String(), "nonexistent_check") {
		t.Errorf("body should name the bad value, got %s", postW.Body.String())
	}
}

func TestBuildChangeSetAcceptsKnownEnumValues(t *testing.T) {
	section, ok := LookupSettingsSection("alerts")
	if !ok {
		t.Fatal("alerts section missing")
	}
	clone := &config.Config{}
	changes := map[string]json.RawMessage{
		"email.disabled_checks": json.RawMessage(`["webshell","perf_memory"]`),
	}

	yamlChanges, errs := buildChangeSet(section, clone, changes)
	if len(errs) > 0 {
		t.Fatalf("buildChangeSet errors = %+v, want none", errs)
	}
	if len(yamlChanges) != 1 {
		t.Fatalf("YAML changes = %+v, want one change", yamlChanges)
	}
	if got := yamlChanges[0].Path; len(got) != 3 || got[0] != "alerts" || got[1] != "email" || got[2] != "disabled_checks" {
		t.Fatalf("YAML change path = %v, want alerts.email.disabled_checks", got)
	}
	if got := clone.Alerts.Email.DisabledChecks; len(got) != 2 || got[0] != "webshell" || got[1] != "perf_memory" {
		t.Fatalf("DisabledChecks = %v, want [webshell perf_memory]", got)
	}
}

// End-to-end companion to TestBuildChangeSetAcceptsKnownEnumValues: a known
// enum value must survive the full POST path (CSRF + ETag + validate + persist)
// and reload from disk, not just the buildChangeSet unit step.
func TestSettingsPOSTAcceptsKnownEnumValues(t *testing.T) {
	// A valid alerts section needs one reachable alert method (the validator
	// probes email SMTP or the webhook URL). Point the webhook at a local test
	// server so the probe succeeds hermetically and the POST reaches persist.
	hookSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(hookSrv.Close)

	body := `hostname: t.example.com
alerts:
  email:
    enabled: false
    to: ["ops@t.example.com"]
    from: csm@t.example.com
  webhook:
    enabled: true
    url: "` + hookSrv.URL + `"
    type: "slack"
  max_per_hour: 20
`
	s, cfgPath := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/alerts", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}

	postReq := settingsAuthedReq("POST", "/api/v1/settings/alerts", "tok",
		`{"changes":{"email.disabled_checks":["webshell","perf_memory"]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("POST code = %d, want 200, body = %s", postW.Code, postW.Body.String())
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload after POST: %v", err)
	}
	if got := loaded.Alerts.Email.DisabledChecks; len(got) != 2 || got[0] != "webshell" || got[1] != "perf_memory" {
		t.Errorf("Alerts.Email.DisabledChecks = %v, want [webshell perf_memory]", got)
	}
}

func TestSettingsPOSTMailLogsRejectsUnknownSource(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
mail_logs:
  source: auto
  units: ["postfix", "dovecot"]
`
	s, _ := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/mail_logs", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/mail_logs", "tok",
		`{"changes":{"source":"kafka"}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 422 {
		t.Fatalf("code = %d, want 422, body = %s", postW.Code, postW.Body.String())
	}
	if !strings.Contains(postW.Body.String(), "kafka") {
		t.Errorf("response should name the bad source, got %s", postW.Body.String())
	}
}

func TestSettingsPOSTThresholdsPreservesRegexAccountExtractor(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
`
	s, cfgPath := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/thresholds", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	want := `regex:user=([^,\s]+)`
	postReq := settingsAuthedReq("POST", "/api/v1/settings/thresholds", "tok",
		`{"changes":{"mail_brute_account_key":"regex:user=([^,\\s]+)"}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("code = %d, body = %s", postW.Code, postW.Body.String())
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Thresholds.MailBruteAccountKey != want {
		t.Fatalf("mail_brute_account_key = %q, want %q", loaded.Thresholds.MailBruteAccountKey, want)
	}
}

func TestSettingsPOSTThresholdsRejectsInvalidAccountExtractor(t *testing.T) {
	body := `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:1"
  max_per_hour: 20
`
	s, _ := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/thresholds", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/thresholds", "tok",
		`{"changes":{"mail_brute_account_key":"regex:user=[^,\\s]+"}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 422 {
		t.Fatalf("code = %d, want 422, body = %s", postW.Code, postW.Body.String())
	}
	if !strings.Contains(postW.Body.String(), "capture group") {
		t.Errorf("response should explain missing capture group, got %s", postW.Body.String())
	}
}

// firewallSettingsTestYAML returns a minimal config with the firewall section
// populated so the settings endpoints have something to roundtrip through.
func firewallSettingsTestYAML() string {
	return `hostname: t.example.com
alerts:
  email:
    enabled: true
    to: ["ops@t.example.com"]
    from: csm@t.example.com
    smtp: "127.0.0.1:25"
  max_per_hour: 20
webui:
  enabled: true
  listen: "0.0.0.0:9443"
firewall:
  enabled: false
  tcp_in: [80, 443, 9443]
  tcp_out: [80, 443]
  udp_in: [53]
  udp_out: [53, 123]
  conn_rate_limit: 200
  conn_limit: 400
  syn_flood_protection: true
  udp_flood: true
  udp_flood_rate: 100
  udp_flood_burst: 500
  deny_ip_limit: 3000
  deny_temp_ip_limit: 500
  smtp_block: false
  smtp_ports: [25, 465, 587]
  log_dropped: true
  log_rate: 5
`
}

func TestSettingsPOSTFirewallIntArrayDedupAndSorts(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())

	getReq := settingsAuthedReq("GET", "/api/v1/settings/firewall", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	if getW.Code != 200 {
		t.Fatalf("GET code = %d, body = %s", getW.Code, getW.Body.String())
	}
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/firewall", "tok",
		`{"changes":{"tcp_in":[443, 9443, 80, 443, 9443]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("POST code = %d, body = %s", postW.Code, postW.Body.String())
	}

	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Firewall == nil {
		t.Fatal("firewall section missing after save")
	}
	want := []int{80, 443, 9443}
	if got := saved.Firewall.TCPIn; !reflect.DeepEqual(got, want) {
		t.Errorf("tcp_in not deduped+sorted: got %v, want %v", got, want)
	}
}

func TestSettingsPOSTRestartResponseNamesPendingSections(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())

	getReq := settingsAuthedReq("GET", "/api/v1/settings/firewall", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/firewall", "tok",
		`{"changes":{"tcp_in":[80,443,9443,2083]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("POST code = %d, body = %s", postW.Code, postW.Body.String())
	}
	var postResp struct {
		PendingRestart  bool                     `json:"pending_restart"`
		PendingSections []pendingSettingsSection `json:"pending_sections"`
	}
	if err := json.Unmarshal(postW.Body.Bytes(), &postResp); err != nil {
		t.Fatal(err)
	}
	if !postResp.PendingRestart {
		t.Fatal("firewall port change should require restart")
	}
	if len(postResp.PendingSections) != 1 || postResp.PendingSections[0].ID != "firewall" {
		t.Fatalf("pending sections = %+v, want firewall", postResp.PendingSections)
	}

	getW = httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	if getW.Code != 200 {
		t.Fatalf("GET code = %d, body = %s", getW.Code, getW.Body.String())
	}
	var getResp struct {
		PendingSections []pendingSettingsSection `json:"pending_sections"`
	}
	if err := json.Unmarshal(getW.Body.Bytes(), &getResp); err != nil {
		t.Fatal(err)
	}
	if len(getResp.PendingSections) != 1 || getResp.PendingSections[0].Title != "Firewall" {
		t.Fatalf("GET pending sections = %+v, want Firewall", getResp.PendingSections)
	}

	thresholdsReq := settingsAuthedReq("GET", "/api/v1/settings/thresholds", "tok", "")
	thresholdsGetW := httptest.NewRecorder()
	s.apiSettingsGet(thresholdsGetW, thresholdsReq)
	thresholdsETag := thresholdsGetW.Header().Get("ETag")
	thresholdsPostReq := settingsAuthedReq("POST", "/api/v1/settings/thresholds", "tok",
		`{"changes":{"mail_queue_warn":42}}`)
	thresholdsPostReq.Header.Set("If-Match", thresholdsETag)
	thresholdsPostReq.Header.Set("X-CSRF-Token", s.csrfToken())
	thresholdsPostW := httptest.NewRecorder()
	s.apiSettingsPost(thresholdsPostW, thresholdsPostReq)
	if thresholdsPostW.Code != 200 {
		t.Fatalf("thresholds POST code = %d, body = %s", thresholdsPostW.Code, thresholdsPostW.Body.String())
	}

	active := config.Active()
	if active == nil {
		t.Fatal("active config is nil")
	}
	if active.Thresholds.MailQueueWarn != 42 {
		t.Fatalf("safe thresholds change was not applied live: mail_queue_warn = %d", active.Thresholds.MailQueueWarn)
	}
	for _, port := range active.Firewall.TCPIn {
		if port == 2083 {
			t.Fatal("safe alerts save promoted pending firewall restart change into active config")
		}
	}
}

func TestSettingsPOSTFirewallIntArrayRejectsOutOfRange(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())

	getReq := settingsAuthedReq("GET", "/api/v1/settings/firewall", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/firewall", "tok",
		`{"changes":{"tcp_in":[80, 443, 70000]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 422 {
		t.Fatalf("code = %d, want 422, body = %s", postW.Code, postW.Body.String())
	}
	if !strings.Contains(postW.Body.String(), "70000") {
		t.Errorf("response should name the offending value, got %s", postW.Body.String())
	}
}

func TestSettingsPOSTFirewallIntArrayRejectsMalformedToken(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())

	getReq := settingsAuthedReq("GET", "/api/v1/settings/firewall", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/firewall", "tok",
		`{"changes":{"tcp_in":["80", "443x"]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 422 {
		t.Fatalf("code = %d, want 422, body = %s", postW.Code, postW.Body.String())
	}
	if !strings.Contains(postW.Body.String(), "443x") {
		t.Errorf("response should name the malformed value, got %s", postW.Body.String())
	}
}

func TestSettingsPOSTFirewallLockoutWarning(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())

	getReq := settingsAuthedReq("GET", "/api/v1/settings/firewall", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/firewall", "tok",
		`{"changes":{"tcp_in":[80, 443]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("save should still succeed (warning, not error): code = %d, body = %s", postW.Code, postW.Body.String())
	}
	var resp struct {
		Warnings []fieldError `json:"warnings"`
	}
	if err := json.Unmarshal(postW.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range resp.Warnings {
		if w.Field == "tcp_in" && strings.Contains(w.Message, "9443") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected lockout warning for tcp_in mentioning WebUI port 9443, got %+v", resp.Warnings)
	}
}

func TestSettingsRestartEndpointRequiresPOST(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", "hostname: t\nalerts:\n  email:\n    enabled: true\n    to: [\"ops@t.example.com\"]\n    from: csm@t.example.com\n    smtp: \"127.0.0.1:1\"\n  max_per_hour: 20\n")
	s.restartDaemon = func() ([]byte, error) { return nil, nil }
	req := settingsAuthedReq("GET", "/api/v1/settings/restart", "tok", "")
	w := httptest.NewRecorder()
	s.apiSettingsRestart(w, req)
	if w.Code != 405 {
		t.Errorf("code = %d, want 405", w.Code)
	}
}
