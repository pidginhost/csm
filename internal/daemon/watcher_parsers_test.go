package daemon

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

func resetEmailRateState() {
	emailRateWindows = sync.Map{}
	emailRateSuppressed = struct {
		mu      sync.Mutex
		domains map[string]time.Time
	}{domains: make(map[string]time.Time)}
}

func withGlobalStore(t *testing.T, fn func(db *store.DB)) {
	t.Helper()

	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	prev := store.Global()
	store.SetGlobal(db)
	defer store.SetGlobal(prev)

	fn(db)
}

func testEmailProtectionConfig() *config.Config {
	cfg := &config.Config{}
	cfg.EmailProtection.RateWarnThreshold = 2
	cfg.EmailProtection.RateCritThreshold = 3
	cfg.EmailProtection.RateWindowMin = 10
	return cfg
}

func TestParseSessionLogLine_DirectLogin(t *testing.T) {
	resetPurgeTrackerState()

	cfg := &config.Config{}
	line := `2026-04-11T12:00:00Z [cpaneld] 198.51.100.20 NEW alice:session method=handle_form_login`

	findings := parseSessionLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "cpanel_login_realtime" {
		t.Fatalf("check = %q, want cpanel_login_realtime", findings[0].Check)
	}
	if !purgeTracker.isPostPurge401("198.51.100.20") {
		purgeTracker.recordPurge("alice")
		if !purgeTracker.isPostPurge401("198.51.100.20") {
			t.Fatal("direct login should record IP-to-account correlation for purge suppression")
		}
	}
}

func TestParseSessionLogLine_PortalSessionSuppressed(t *testing.T) {
	resetPurgeTrackerState()

	cfg := &config.Config{}
	line := `2026-04-11T12:00:00Z [cpaneld] 198.51.100.21 NEW alice:session method=create_user_session`

	findings := parseSessionLogLine(line, cfg)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for portal-created session, got %v", findings)
	}
}

func TestParseSessionLogLine_SuppressedByConfig(t *testing.T) {
	resetPurgeTrackerState()

	cfg := &config.Config{}
	cfg.Suppressions.SuppressCpanelLogin = true
	line := `2026-04-11T12:00:00Z [cpaneld] 198.51.100.22 NEW alice:session method=handle_form_login`

	findings := parseSessionLogLine(line, cfg)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when cPanel login suppression is enabled, got %v", findings)
	}
}

func TestParseSessionLogLine_PasswordPurge(t *testing.T) {
	resetPurgeTrackerState()

	cfg := &config.Config{}
	line := `2026-04-11T12:00:00Z [cpaneld] PURGE alice:password_change`

	findings := parseSessionLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "cpanel_password_purge_realtime" {
		t.Fatalf("check = %q, want cpanel_password_purge_realtime", findings[0].Check)
	}
}

func TestParseSecureLogLine_AcceptedSSHLogin(t *testing.T) {
	cfg := &config.Config{}
	line := `Apr 11 12:00:00 host sshd[12345]: Accepted password for root from 198.51.100.30 port 54321 ssh2`

	findings := parseSecureLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "ssh_login_realtime" {
		t.Fatalf("check = %q, want ssh_login_realtime", findings[0].Check)
	}
}

func TestParseSecureLogLine_IgnoresInfraAndLoopback(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"198.51.100.31/32"}}

	infraLine := `Apr 11 12:00:00 host sshd[12345]: Accepted password for root from 198.51.100.31 port 54321 ssh2`
	if findings := parseSecureLogLine(infraLine, cfg); len(findings) != 0 {
		t.Fatalf("infra IP should be ignored, got %v", findings)
	}

	loopbackLine := `Apr 11 12:00:00 host sshd[12345]: Accepted password for root from 127.0.0.1 port 54321 ssh2`
	if findings := parseSecureLogLine(loopbackLine, cfg); len(findings) != 0 {
		t.Fatalf("loopback IP should be ignored, got %v", findings)
	}
}

func TestParseEximLogLine_FrozenMessage(t *testing.T) {
	cfg := &config.Config{}
	line := `2026-04-11 12:00:00 1abc23-000456-AB frozen`

	findings := parseEximLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "exim_frozen_realtime" {
		t.Fatalf("check = %q, want exim_frozen_realtime", findings[0].Check)
	}
}

func TestParseEximLogLine_CredentialLeakInSubject(t *testing.T) {
	cfg := &config.Config{}
	line := `2026-04-11 12:00:00 1abc23-000456-AB <= sender@example.com H=mail.example.com [203.0.113.42] P=esmtpsa X=TLS1.3 A=dovecot_login:sender@example.com S=1234 T="smtp.example.com:587,user@example.com,SuperSecretPassword"`

	findings := parseEximLogLine(line, cfg)
	if len(findings) == 0 {
		t.Fatalf("expected credential leak findings, got none")
	}
	foundCritical := false
	for _, f := range findings {
		if f.Check == "email_credential_leak" && strings.Contains(f.Message, "SMTP credentials leaked") {
			foundCritical = true
			break
		}
	}
	if !foundCritical {
		t.Fatalf("expected critical SMTP credential leak finding, got %v", findings)
	}
}

func TestParseEximLogLine_DovecotAuthFailure(t *testing.T) {
	cfg := &config.Config{}
	line := `2026-04-11 12:00:00 dovecot_login authenticator failed for H=(mail.example.com) [198.51.100.40]:54321: 535 Incorrect authentication data (set_id=user@example.com)`

	findings := parseEximLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "email_auth_failure_realtime" {
		t.Fatalf("check = %q, want email_auth_failure_realtime", findings[0].Check)
	}
}

func TestParseEximLogLine_OutgoingMailHoldDedup(t *testing.T) {
	withGlobalStore(t, func(db *store.DB) {
		cfg := &config.Config{}
		line := `2026-04-11 12:00:00 Sender office@example.com has an outgoing mail hold`

		first := parseEximLogLine(line, cfg)
		if len(first) != 1 {
			t.Fatalf("expected first hold line to alert once, got %d: %v", len(first), first)
		}
		if first[0].Check != "email_compromised_account" {
			t.Fatalf("check = %q, want email_compromised_account", first[0].Check)
		}

		second := parseEximLogLine(line, cfg)
		if len(second) != 0 {
			t.Fatalf("expected second hold line to be deduped, got %v", second)
		}

		if got := db.GetMetaString("email_hold:example.com"); got == "" {
			t.Fatal("expected dedup marker to be written to store")
		}
	})
}

func TestParseEximLogLine_EmailRateIntegration(t *testing.T) {
	resetEmailRateState()

	cfg := testEmailProtectionConfig()
	line := `2026-04-11 12:00:00 1abc23-000456-AB <= sender@example.com H=mail.example.com [203.0.113.42] P=esmtpsa X=TLS1.3 A=dovecot_login:sender@example.com S=1234 T="Normal subject"`

	if findings := parseEximLogLine(line, cfg); len(findings) != 0 {
		t.Fatalf("expected no findings below rate threshold, got %v", findings)
	}

	second := parseEximLogLine(line, cfg)
	if len(second) != 1 {
		t.Fatalf("expected warning finding at threshold, got %d: %v", len(second), second)
	}
	if second[0].Check != "email_rate_warning" {
		t.Fatalf("check = %q, want email_rate_warning", second[0].Check)
	}

	third := parseEximLogLine(line, cfg)
	if len(third) != 1 {
		t.Fatalf("expected critical finding at critical threshold, got %d: %v", len(third), third)
	}
	if third[0].Check != "email_rate_critical" {
		t.Fatalf("check = %q, want email_rate_critical", third[0].Check)
	}
}
