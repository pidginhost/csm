package alert

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func httpClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}

	return nil
}

// SendPhpanelWebhookFinding posts a single finding to the configured phpanel
// endpoint, signing the body with HMAC-SHA256 in X-CSM-Signature. Stateless;
// caller is responsible for filtering / batching.
func SendPhpanelWebhookFinding(cfg *config.Config, f Finding) error {
	if cfg.Alerts.Webhook.URL == "" {
		return fmt.Errorf("phpanel webhook URL not set")
	}
	if cfg.Alerts.Webhook.HMACSecret == "" {
		return fmt.Errorf("phpanel webhook HMAC secret not configured")
	}
	payload := map[string]interface{}{
		"hostname":  cfg.Hostname,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"finding":   f,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling phpanel payload: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(cfg.Alerts.Webhook.HMACSecret))
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("phpanel webhook HTTP %d", resp.StatusCode)
	}
	return nil
}
