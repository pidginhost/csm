package alert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditSourcesDoNotStartNotificationDelivery(t *testing.T) {
	resetAuditSinksForTest()
	t.Cleanup(resetAuditSinksForTest)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := cfgWithJSONLAudit(t, path)
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	// A source-only audit must not need notification state or credentials.
	cfg.StatePath = ""
	if err := DispatchWithSources(cfg, nil, []Finding{{Check: "pam_bruteforce", Message: "source observation"}}); err != nil {
		t.Fatalf("audit-only source entered delivery: %v", err)
	}
	resetAuditSinksForTest()
	if data, err := os.ReadFile(path); err != nil || len(data) == 0 {
		t.Fatalf("source audit missing: error=%v", err)
	}
}

func TestAuditSourcesShareTimestampWithoutMutatingInputs(t *testing.T) {
	resetAuditSinksForTest()
	t.Cleanup(resetAuditSinksForTest)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := cfgWithJSONLAudit(t, path)
	source := []Finding{{Check: "wp_login_bruteforce", Message: "source observation"}}
	notifications := append([]Finding(nil), source...)
	if err := DispatchWithSources(cfg, notifications, source); err != nil {
		t.Fatal(err)
	}
	resetAuditSinksForTest()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.TrimSpace(string(data)), "\n") != 0 {
		t.Fatal("overlapping unstamped source emitted duplicate audit rows")
	}
	var event AuditEvent
	if decodeErr := json.Unmarshal(data, &event); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if event.FindingID == "" || event.Timestamp.IsZero() {
		t.Fatal("source identity or observation time missing")
	}
	if !source[0].Timestamp.IsZero() || !notifications[0].Timestamp.IsZero() {
		t.Fatal("dispatch mutated caller-owned timestamps")
	}
}
