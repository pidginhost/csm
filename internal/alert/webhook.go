package alert

import (
	"bytes"
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
