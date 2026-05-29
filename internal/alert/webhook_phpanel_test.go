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
	"time"

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

func TestSendPhpanelWebhook_EnvSecretOverridesInlineSecret(t *testing.T) {
	t.Setenv("CSM_PHPANEL_HMAC_TEST", "env-secret")
	var capturedSig, capturedBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSig = r.Header.Get("X-CSM-Signature")
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{Hostname: "host"}
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "inline-secret"
	cfg.Alerts.Webhook.HMACSecretEnv = "CSM_PHPANEL_HMAC_TEST"

	if err := SendPhpanelWebhookFinding(cfg, Finding{Check: "test", Severity: High}); err != nil {
		t.Fatal(err)
	}

	mac := hmac.New(sha256.New, []byte("env-secret"))
	mac.Write([]byte(capturedBody))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if capturedSig != want {
		t.Fatalf("expected env-secret signature %s, got %s", want, capturedSig)
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

func TestDispatchPhpanelWebhookAlwaysUsesSignedPerFinding(t *testing.T) {
	var requests int32
	var signatures []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		signatures = append(signatures, r.Header.Get("X-CSM-Signature"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "secret"
	cfg.Alerts.Webhook.PerFinding = false

	findings := []Finding{
		{Check: "a", Message: "a", Severity: Critical, Timestamp: time.Now()},
		{Check: "b", Message: "b", Severity: Critical, Timestamp: time.Now()},
	}
	if err := Dispatch(cfg, findings); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&requests) != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	for _, sig := range signatures {
		if !strings.HasPrefix(sig, "sha256=") {
			t.Fatalf("missing phpanel signature in %q", sig)
		}
	}
}

func TestDispatchPhpanelWebhookBypassesOperatorRateLimit(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 1
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "secret"

	for i := 0; i < 3; i++ {
		finding := Finding{
			Check:     "ssh_bruteforce",
			Message:   "failed login " + string(rune('a'+i)),
			Severity:  Warning,
			SourceIP:  "203.0.113.10",
			Timestamp: time.Now(),
		}
		if err := Dispatch(cfg, []Finding{finding}); err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt32(&requests); got != 3 {
		t.Fatalf("phpanel webhook requests = %d, want 3", got)
	}
	if got := readRateLimitCount(t, cfg.StatePath); got != 0 {
		t.Fatalf("rate-limit count = %d, want 0", got)
	}
}

func TestDispatchPhpanelWebhookBypassesBlockedAlertSuppression(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 1
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "secret"
	cfg.Suppressions.SuppressBlockedAlerts = true
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	finding := Finding{
		Check:     "ip_reputation",
		Message:   "Known malicious IP detected: 203.0.113.10",
		Severity:  Warning,
		SourceIP:  "203.0.113.10",
		Timestamp: time.Now(),
	}
	if err := Dispatch(cfg, []Finding{finding}); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("phpanel webhook requests = %d, want 1", got)
	}
}

func TestDispatchPhpanelWebhookErrorIsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "secret"

	err := Dispatch(cfg, []Finding{{Check: "a", Message: "a", Severity: Critical, Timestamp: time.Now()}})
	if err == nil {
		t.Fatal("expected phpanel webhook error")
	}
	if !strings.Contains(err.Error(), "phpanel webhook") {
		t.Fatalf("err = %v, want phpanel webhook context", err)
	}
}
