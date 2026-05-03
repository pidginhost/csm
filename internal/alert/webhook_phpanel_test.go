package alert

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestSendPhpanelWebhook_SignsBody(t *testing.T) {
	secret := "panel-shared-secret"
	var requests int32
	var capturedSig, capturedBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		capturedSig = r.Header.Get("X-CSM-Signature")
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{Hostname: "host"}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = secret
	cfg.Alerts.Webhook.PerFinding = true

	finding := Finding{Check: "test", Severity: High, Message: "x"}
	if err := SendPhpanelWebhookFinding(cfg, finding); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&requests) != 1 {
		t.Fatalf("expected 1 request, got %d", requests)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(capturedBody))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if capturedSig != want {
		t.Fatalf("expected sig %s, got %s", want, capturedSig)
	}
	if !strings.Contains(capturedBody, `"check":"test"`) {
		t.Fatalf("body should embed finding JSON, got %s", capturedBody)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(capturedBody), &parsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed["finding"]; !ok {
		t.Fatalf("expected payload to wrap finding under 'finding' key, got %v", parsed)
	}
}

func TestSendPhpanelWebhook_NoSecretIsError(t *testing.T) {
	cfg := &config.Config{Hostname: "h"}
	cfg.Alerts.Webhook.URL = "http://example.invalid"
	finding := Finding{Check: "x", Severity: High}
	if err := SendPhpanelWebhookFinding(cfg, finding); err == nil {
		t.Fatal("expected error when HMAC secret is unset")
	}
}

func TestSendPhpanelWebhook_4xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	cfg := &config.Config{Hostname: "h"}
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "s"
	if err := SendPhpanelWebhookFinding(cfg, Finding{Check: "x", Severity: High}); err == nil {
		t.Fatal("expected error on HTTP 403")
	}
}
