package alert

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// webhookTransport is the shared *http.Transport reused across every
// webhook dispatch. Reusing one transport keeps the underlying TCP /
// TLS connections in its keepalive pool so hosts that fire hundreds
// of webhooks per hour avoid a new handshake per alert. Per-call
// timeouts stay configurable via httpClient: each call wraps the
// shared transport in a fresh *http.Client carrying the requested
// timeout. http.DefaultTransport already configures sensible
// defaults; reuse it directly rather than instantiating a separate
// pool that would shadow Go's HTTP/2 / proxy plumbing.
var webhookTransport http.RoundTripper = http.DefaultTransport

const maxWebhookResponseDrainBytes int64 = 512 << 10
const maxWebhookResponseDrainDuration = 250 * time.Millisecond

// httpClient returns a webhook client with the requested timeout
// backed by the shared transport, so the keepalive pool is shared
// across dispatches without losing per-call timeout configurability.
func httpClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: webhookTransport}
}

// SetWebhookTransportForTest lets tests inject a fake RoundTripper.
// Not safe for concurrent calls; tests should set up before parallel
// dispatch and restore after.
func SetWebhookTransportForTest(rt http.RoundTripper) (restore func()) {
	prev := webhookTransport
	webhookTransport = rt
	return func() { webhookTransport = prev }
}

func closeWebhookResponseBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}

	if resp.Close || resp.ContentLength == 0 || resp.ContentLength > maxWebhookResponseDrainBytes {
		_ = resp.Body.Close()
		return
	}

	done := make(chan struct{})
	go func() {
		// Read one sentinel byte past the reuse limit so an exactly-at-limit
		// response still reaches the underlying EOF and can be pooled.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxWebhookResponseDrainBytes+1))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(maxWebhookResponseDrainDuration):
		// A slow or streaming response is not worth holding alert dispatch
		// open just to preserve a keepalive connection.
	}
	_ = resp.Body.Close()
}

func SendWebhook(cfg *config.Config, subject, body string) error {
	url := cfg.Alerts.Webhook.URL
	if url == "" {
		return fmt.Errorf("no webhook URL configured")
	}

	var payload []byte
	var err error

	switch cfg.Alerts.Webhook.Type {
	case "slack":
		payload, err = json.Marshal(map[string]string{
			"text": fmt.Sprintf("*%s*\n```\n%s\n```", subject, body),
		})
	case "discord":
		payload, err = json.Marshal(map[string]string{
			"content": fmt.Sprintf("**%s**\n```\n%s\n```", subject, body),
		})
	default:
		payload, err = json.Marshal(map[string]string{
			"subject": subject,
			"body":    body,
		})
	}
	if err != nil {
		return fmt.Errorf("marshaling webhook payload: %w", err)
	}

	client := httpClient(10 * time.Second)
	resp, err := client.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook POST: %w", err)
	}
	defer closeWebhookResponseBody(resp)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}

	return nil
}

// SendWebhookJSON posts a pre-built JSON payload to the configured webhook
// URL. Senders that need a structured body (not the slack/discord subject
// envelope) use this. No-op when no URL is configured.
func SendWebhookJSON(cfg *config.Config, payload any) error {
	url := cfg.Alerts.Webhook.URL
	if url == "" {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling webhook payload: %w", err)
	}
	client := httpClient(10 * time.Second)
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook POST: %w", err)
	}
	defer closeWebhookResponseBody(resp)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

// SendPhpanelWebhookFinding posts a single finding to the configured phpanel
// endpoint, signing the body with HMAC-SHA256 in X-CSM-Signature. Stateless;
// caller is responsible for filtering / batching.
func SendPhpanelWebhookFinding(cfg *config.Config, f Finding) error {
	delivery := phpanelDeliveryConfig{
		hostname:      cfg.Hostname,
		url:           cfg.Alerts.Webhook.URL,
		hmacSecret:    cfg.Alerts.Webhook.HMACSecret,
		hmacSecretEnv: cfg.Alerts.Webhook.HMACSecretEnv,
	}
	return sendQueuedPhpanelWebhookFinding(delivery, queuedPhpanelFinding{Finding: f, Timestamp: time.Now().UTC()})
}

func sendQueuedPhpanelWebhookFinding(delivery phpanelDeliveryConfig, queued queuedPhpanelFinding) error {
	cfg := &config.Config{Hostname: delivery.hostname}
	cfg.Alerts.Webhook.URL = delivery.url
	cfg.Alerts.Webhook.HMACSecret = delivery.hmacSecret
	cfg.Alerts.Webhook.HMACSecretEnv = delivery.hmacSecretEnv
	if cfg.Alerts.Webhook.URL == "" {
		return fmt.Errorf("phpanel webhook URL not set")
	}
	secret := phpanelWebhookSecret(cfg)
	if secret == "" {
		return fmt.Errorf("phpanel webhook HMAC secret not configured")
	}
	payload := map[string]interface{}{
		"hostname":  cfg.Hostname,
		"timestamp": queued.Timestamp.Format(time.RFC3339),
		"finding":   queued.Finding,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling phpanel payload: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodPost, cfg.Alerts.Webhook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSM-Signature", sig)
	req.Header.Set("X-CSM-Hostname", cfg.Hostname)
	req.Header.Set("User-Agent", "csm")

	client := httpClient(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("phpanel webhook POST: %w", err)
	}
	defer closeWebhookResponseBody(resp)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("phpanel webhook HTTP %d", resp.StatusCode)
	}
	return nil
}

func phpanelWebhookSecret(cfg *config.Config) string {
	if cfg.Alerts.Webhook.HMACSecretEnv != "" {
		if v := os.Getenv(cfg.Alerts.Webhook.HMACSecretEnv); v != "" {
			return v
		}
	}
	return cfg.Alerts.Webhook.HMACSecret
}
