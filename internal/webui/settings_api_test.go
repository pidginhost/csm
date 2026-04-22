package webui

import (
	"context"
	"encoding/json"
	"fmt"
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
	if serr := integrity.SignAndSaveAtomic(cfg, "sha256:testbinary"); serr != nil {
		t.Fatal(serr)
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
  netblock_threshold: 3
`
	s, cfgPath := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/auto_response", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag from GET")
	}

	postReq := settingsAuthedReq("POST", "/api/v1/settings/auto_response", "tok", `{"changes":{"block_ips":true,"netblock_threshold":5}}`)
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
	if live.AutoResponse.NetBlockThreshold != 5 {
		t.Errorf("NetBlockThreshold = %d", live.AutoResponse.NetBlockThreshold)
	}
	loaded, _ := config.Load(cfgPath)
	if !loaded.AutoResponse.BlockIPs {
		t.Error("disk not updated")
	}
	if loaded.Integrity.ConfigHash != resp.NewETag {
		t.Errorf("disk config_hash = %q, new_etag = %q", loaded.Integrity.ConfigHash, resp.NewETag)
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
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
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

func TestSettingsPOSTAcceptsKnownEnumValues(t *testing.T) {
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
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
	s, _ := newSettingsTestServer(t, "tok", body)

	getReq := settingsAuthedReq("GET", "/api/v1/settings/alerts", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/alerts", "tok",
		`{"changes":{"email.disabled_checks":["webshell","perf_memory"]}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiSettingsPost(postW, postReq)

	if postW.Code != 200 {
		t.Fatalf("code = %d, body = %s", postW.Code, postW.Body.String())
	}
	live := config.Active()
	if len(live.Alerts.Email.DisabledChecks) != 2 {
		t.Fatalf("DisabledChecks = %v, want 2 entries", live.Alerts.Email.DisabledChecks)
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
