package alert

import (
	"testing"
	"time"
)

func TestDeduplicate(t *testing.T) {
	findings := []Finding{
		{Check: "a", Message: "msg1"},
		{Check: "a", Message: "msg1"}, // duplicate
		{Check: "b", Message: "msg2"},
		{Check: "a", Message: "msg1"}, // duplicate
		{Check: "b", Message: "msg3"},
	}

	result := Deduplicate(findings)
	if len(result) != 3 {
		t.Errorf("expected 3 unique findings, got %d", len(result))
	}
}

func TestDeduplicateEmpty(t *testing.T) {
	result := Deduplicate(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result))
	}
}

func TestFindingKey(t *testing.T) {
	f := Finding{Check: "test", Message: "hello"}
	if f.Key() != "test:hello" {
		t.Errorf("expected 'test:hello', got '%s'", f.Key())
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{Warning, "WARNING"},
		{High, "HIGH"},
		{Critical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestFormatAlert(t *testing.T) {
	findings := []Finding{
		{Severity: Critical, Check: "test", Message: "bad thing", Timestamp: time.Now()},
	}
	body := FormatAlert("test-host", findings)
	if body == "" {
		t.Error("expected non-empty alert body")
	}
	if !contains(body, "SECURITY ALERT") {
		t.Error("expected SECURITY ALERT in body")
	}
	if !contains(body, "test-host") {
		t.Error("expected hostname in body")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
