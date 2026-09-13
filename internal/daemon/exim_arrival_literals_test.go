package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/eximlog"
)

func TestAuthenticatedArrivalWithAddressLiteral(t *testing.T) {
	withOwnerTable(t)
	resetEmailRateState()
	t.Cleanup(resetEmailRateState)
	line := `2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.net H=mail.example [203.0.113.5]:2525 P=esmtpsa A=dovecot_login:user@example.com S=100 id=notice@[192.0.2.1]`
	if got := extractAuthUser(line); got != "user@example.com" {
		t.Errorf("authenticated user = %q, want user@example.com", got)
	}
	if got := eximlog.ClientIP(line); got != "203.0.113.5" {
		t.Errorf("client IP = %q, want 203.0.113.5", got)
	}
	var findings []alert.Finding
	for range 3 {
		findings = append(findings, parseEximLogLine(line, testEmailProtectionConfig())...)
	}
	for _, f := range findings {
		if f.Check == "email_rate_critical" {
			if f.TenantID != "alice" {
				t.Fatalf("rate finding tenant = %q, want alice", f.TenantID)
			}
			return
		}
	}
	t.Fatal("authenticated arrivals were not counted")
}
