package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestSendWebhookJSONPostsBody(t *testing.T) {
	var gotBody map[string]any
	var gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Alerts.Webhook.URL = srv.URL

	payload := map[string]any{"text": "hi", "csm": map[string]any{"event": "block_digest"}}
	if err := SendWebhookJSON(cfg, payload); err != nil {
		t.Fatalf("SendWebhookJSON: %v", err)
	}
	if gotBody["text"] != "hi" {
		t.Errorf("server did not receive text field: %+v", gotBody)
	}
	if gotType != "application/json" {
		t.Errorf("content-type = %q, want application/json", gotType)
	}
}

func TestSendWebhookJSONNoopWhenURLEmpty(t *testing.T) {
	if err := SendWebhookJSON(&config.Config{}, map[string]any{"x": 1}); err != nil {
		t.Errorf("empty URL should be a no-op, got %v", err)
	}
}

func TestSendWebhookJSONErrorsOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Alerts.Webhook.URL = srv.URL
	if err := SendWebhookJSON(cfg, map[string]any{"x": 1}); err == nil {
		t.Error("expected error on 500 status, got nil")
	}
}
