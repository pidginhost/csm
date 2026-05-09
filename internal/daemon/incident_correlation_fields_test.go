package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
)

// These tests guard the contract that high-volume realtime detectors
// populate the structured correlation fields on alert.Finding. Without
// them, KeyFor returns an empty key and the incident correlator drops
// the finding on the floor — which is what shipped before the fix and
// left the /incident "Correlated" tab permanently empty on production.

func TestEmailAuthFailureRealtimePopulatesCorrelationFields(t *testing.T) {
	line := `2026-05-09 19:26:23 dovecot_login authenticator failed for H=(localhost) [198.51.100.1]:55330: 535 Incorrect authentication data (set_id=alice@example.com)`
	cfg := &config.Config{}

	findings := parseEximLogLine(line, cfg)
	if len(findings) == 0 {
		t.Fatal("expected a finding for dovecot auth failure")
	}
	var f *struct {
		SourceIP, Mailbox, Domain string
	}
	for i := range findings {
		if findings[i].Check == "email_auth_failure_realtime" {
			f = &struct {
				SourceIP, Mailbox, Domain string
			}{findings[i].SourceIP, findings[i].Mailbox, findings[i].Domain}
			break
		}
	}
	if f == nil {
		t.Fatal("no email_auth_failure_realtime finding emitted")
	}
	if f.SourceIP != "198.51.100.1" {
		t.Errorf("SourceIP = %q, want 198.51.100.1", f.SourceIP)
	}
	if f.Mailbox != "alice@example.com" {
		t.Errorf("Mailbox = %q, want alice@example.com", f.Mailbox)
	}
	if f.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", f.Domain)
	}

	// Round-trip through KeyFor — the regression we are guarding against
	// is "KeyFor returns empty so correlator silently drops the finding".
	for i := range findings {
		if findings[i].Check != "email_auth_failure_realtime" {
			continue
		}
		k := incident.KeyFor(findings[i])
		if k.IsEmpty() {
			t.Fatalf("KeyFor returned empty key for %+v", findings[i])
		}
	}
}

func TestSSHLoginRealtimePopulatesSourceIP(t *testing.T) {
	line := `May  9 12:00:00 host sshd[1234]: Accepted publickey for alice from 203.0.113.5 port 55555 ssh2: RSA SHA256:xxx`
	cfg := &config.Config{}

	findings := parseSecureLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].SourceIP != "203.0.113.5" {
		t.Errorf("SourceIP = %q, want 203.0.113.5", findings[0].SourceIP)
	}
	if findings[0].TenantID != "alice" {
		t.Errorf("TenantID = %q, want alice", findings[0].TenantID)
	}
	if incident.KeyFor(findings[0]).IsEmpty() {
		t.Errorf("KeyFor returned empty key — finding will not correlate")
	}
}

func TestModSecApacheDenyPopulatesCorrelationFields(t *testing.T) {
	line := `[Wed Apr 01 15:15:05.234401 2026] [error] [client 198.51.100.164] ModSecurity: Access denied with code 403, [Rule: 'TX:content_type' '!@within %{tx.allowed_request_content_type}'] [id "920420"] [msg "Request content type is not allowed by policy"] [logdata "|text/html|"] [severity "CRITICAL"] [hostname "www.example.com"] [uri "/xmlrpc.php"]`
	cfg := &config.Config{}

	findings := parseModSecLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.SourceIP != "198.51.100.164" {
		t.Errorf("SourceIP = %q, want 198.51.100.164", f.SourceIP)
	}
	if f.Domain != "www.example.com" {
		t.Errorf("Domain = %q, want www.example.com", f.Domain)
	}
	if incident.KeyFor(f).IsEmpty() {
		t.Errorf("KeyFor returned empty key — finding will not correlate")
	}
}

func TestEmailRateLimitPopulatesMailboxAndDomain(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.RateWindowMin = 60
	cfg.EmailProtection.RateWarnThreshold = 1
	cfg.EmailProtection.RateCritThreshold = 100

	findings := checkEmailRate("bob@example.org", cfg)
	if len(findings) == 0 {
		t.Fatal("expected at least one rate finding at warn threshold")
	}
	f := findings[0]
	if f.Mailbox != "bob@example.org" {
		t.Errorf("Mailbox = %q, want bob@example.org", f.Mailbox)
	}
	if f.Domain != "example.org" {
		t.Errorf("Domain = %q, want example.org", f.Domain)
	}
	if incident.KeyFor(f).IsEmpty() {
		t.Errorf("KeyFor returned empty key — finding will not correlate")
	}
}

func TestMailboxOnlyDistinguishesMailboxFromBareDomain(t *testing.T) {
	if got := mailboxOnly("alice@example.com"); got != "alice@example.com" {
		t.Errorf("full mailbox: got %q", got)
	}
	if got := mailboxOnly("example.com"); got != "" {
		t.Errorf("bare domain: got %q, want empty (so Domain field owns it)", got)
	}
	if got := mailboxOnly(""); got != "" {
		t.Errorf("empty: got %q", got)
	}
}
