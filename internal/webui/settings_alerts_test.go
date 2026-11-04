package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestSettingsAlertsKeepLiveDigestDelivery(t *testing.T) {
	hook := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(hook.Close)
	s, cfgPath := newSettingsTestServer(t, "tok", `hostname: alerts.example.test
alerts:
  webhook:
    enabled: true
    url: "`+hook.URL+`"
  block_digest:
    enabled: true
`)

	save := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		get := httptest.NewRecorder()
		s.apiSettingsGet(get, settingsAuthedReq("GET", "/api/v1/settings/alerts", "tok", ""))
		if get.Code != http.StatusOK {
			t.Fatalf("GET settings: %d; %s", get.Code, get.Body.String())
		}
		req := settingsAuthedReq("POST", "/api/v1/settings/alerts", "tok", body)
		req.Header.Set("If-Match", get.Header().Get("ETag"))
		setSessionCSRF(s, req)
		w := httptest.NewRecorder()
		s.apiSettingsPost(w, req)
		return w
	}

	// Disabling the digest is saved for restart. It is still running until then.
	w := save(`{"changes":{"block_digest.enabled":false}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("disable digest: %d; %s", w.Code, w.Body.String())
	}
	live := config.Active()
	if !live.Alerts.BlockDigest.Enabled {
		t.Fatal("digest stopped before restart")
	}
	diskBefore, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	diskCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if diskCfg.Alerts.BlockDigest.Enabled {
		t.Fatal("digest disable was not saved")
	}
	var applies int
	s.SetConfigAppliedHook(func() { applies++ })

	// The last channel cannot be disabled live while the digest still needs it.
	w = save(`{"changes":{"webhook.enabled":false}}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("disable last live digest channel: %d, want 422; %s", w.Code, w.Body.String())
	}
	if config.Active() != live || !config.Active().Alerts.Webhook.Enabled || applies != 0 {
		t.Fatal("rejected save changed live config or invoked the apply hook")
	}
	diskAfter, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(diskBefore, diskAfter) {
		t.Fatal("rejected save changed the signed config on disk")
	}
}

func TestSettingsAlertsDisableLastChannelWithoutDigest(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", `hostname: alerts.example.test
alerts:
  webhook:
    enabled: true
    url: "https://alerts.example.test/hook"
`)
	get := httptest.NewRecorder()
	s.apiSettingsGet(get, settingsAuthedReq("GET", "/api/v1/settings/alerts", "tok", ""))
	if get.Code != http.StatusOK {
		t.Fatalf("GET settings: %d; %s", get.Code, get.Body.String())
	}
	req := settingsAuthedReq("POST", "/api/v1/settings/alerts", "tok", `{"changes":{"webhook.enabled":false}}`)
	req.Header.Set("If-Match", get.Header().Get("ETag"))
	setSessionCSRF(s, req)
	w := httptest.NewRecorder()
	s.apiSettingsPost(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("disable last channel: %d; %s", w.Code, w.Body.String())
	}
	var response struct {
		Warnings []fieldError `json:"warnings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	foundWarning := false
	for _, warning := range response.Warnings {
		if warning.Field == "alerts" {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatal("missing no-channel warning")
	}
	disk, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []*config.Config{config.Active(), disk} {
		if cfg.Alerts.Email.Enabled || cfg.Alerts.Webhook.Enabled {
			t.Fatal("disabled channels were not saved and applied live")
		}
	}
	alertResponse := httptest.NewRecorder()
	s.apiTestAlert(alertResponse, httptest.NewRequest("POST", "/api/v1/test-alert", nil))
	if alertResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("test alert with live channels off: %d; %s", alertResponse.Code, alertResponse.Body.String())
	}
}
