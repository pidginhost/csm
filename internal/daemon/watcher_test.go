package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestExtractAuthUser(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{
			`2026-04-04 10:15:23 1abc23-000456-AB <= user@example.com H=mail.example.com [203.0.113.42] P=esmtpsa X=TLS1.3 A=dovecot_login:user@example.com S=1234 T="Test"`,
			"user@example.com",
		},
		{
			`2026-04-04 10:15:23 1abc23-000456-AB <= sender@test.org H=host [1.2.3.4] A=dovecot_plain:sender@test.org S=512`,
			"sender@test.org",
		},
		{
			`2026-04-04 10:15:23 1abc23-000456-AB <= bounce@example.com H=host [1.2.3.4] P=esmtps S=1024`,
			"", // no A=dovecot_ - not authenticated
		},
		{
			`2026-04-04 10:15:23 1abc23-000456-AB => user@example.com R=lookuphost T=remote_smtp`,
			"", // delivery line, not acceptance
		},
		{
			`2026-04-04 10:15:23 frozen message`,
			"", // no <= marker
		},
	}

	for _, tt := range tests {
		got := extractAuthUser(tt.line)
		if got != tt.want {
			t.Errorf("extractAuthUser(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestRateWindow_AddAndCount(t *testing.T) {
	rw := &rateWindow{}
	now := time.Now()
	windowDur := 10 * time.Minute

	// Add 5 timestamps
	for i := 0; i < 5; i++ {
		rw.add(now.Add(time.Duration(i) * time.Second))
	}

	count := rw.countInWindow(now, windowDur)
	if count != 5 {
		t.Errorf("countInWindow = %d, want 5", count)
	}
}

func TestRateWindow_PruneOld(t *testing.T) {
	rw := &rateWindow{}
	now := time.Now()
	windowDur := 10 * time.Minute

	// Add timestamps: 3 old (outside window), 2 recent
	rw.add(now.Add(-20 * time.Minute))
	rw.add(now.Add(-15 * time.Minute))
	rw.add(now.Add(-11 * time.Minute))
	rw.add(now.Add(-5 * time.Minute))
	rw.add(now.Add(-1 * time.Minute))

	count := rw.countInWindow(now, windowDur)
	if count != 2 {
		t.Errorf("countInWindow = %d, want 2", count)
	}

	// After prune, old entries should be removed
	rw.prune(now, windowDur)
	if len(rw.times) != 2 {
		t.Errorf("after prune, len(times) = %d, want 2", len(rw.times))
	}
}

func TestRateWindow_Empty(t *testing.T) {
	rw := &rateWindow{}
	now := time.Now()
	windowDur := 10 * time.Minute

	count := rw.countInWindow(now, windowDur)
	if count != 0 {
		t.Errorf("countInWindow on empty = %d, want 0", count)
	}

	rw.prune(now, windowDur)
	if len(rw.times) != 0 {
		t.Errorf("after prune on empty, len = %d, want 0", len(rw.times))
	}
}

func TestIsHighVolumeSender(t *testing.T) {
	allowlist := []string{"mailer@example.com", "noreply@test.org"}

	tests := []struct {
		user string
		want bool
	}{
		{"mailer@example.com", true},
		{"noreply@test.org", true},
		{"MAILER@EXAMPLE.COM", true}, // case-insensitive
		{"user@example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isHighVolumeSender(tt.user, allowlist)
		if got != tt.want {
			t.Errorf("isHighVolumeSender(%q) = %v, want %v", tt.user, got, tt.want)
		}
	}
}

func TestExtractDomainFromEmail(t *testing.T) {
	tests := []struct {
		email string
		want  string
	}{
		{"user@example.com", "example.com"},
		{"user@sub.example.com", "sub.example.com"},
		{"nodomain", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := extractDomainFromEmail(tt.email)
		if got != tt.want {
			t.Errorf("extractDomainFromEmail(%q) = %q, want %q", tt.email, got, tt.want)
		}
	}
}

func TestEmailRateHighVolumeSenderSkip(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.HighVolumeSenders = []string{"hvs-mailer@hvs-skip.test"}
	cfg.EmailProtection.RateWarnThreshold = 5
	cfg.EmailProtection.RateCritThreshold = 10
	cfg.EmailProtection.RateWindowMin = 10

	// Use a unique user that matches the allowlist
	for i := 0; i < 20; i++ {
		findings := checkEmailRate("hvs-mailer@hvs-skip.test", cfg)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for allowlisted sender, got %d on iteration %d", len(findings), i)
		}
	}

	// Clean up
	emailRateWindows.Delete("hvs-mailer@hvs-skip.test")
}

func TestEmailRateThresholds(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.HighVolumeSenders = nil
	cfg.EmailProtection.RateWarnThreshold = 5
	cfg.EmailProtection.RateCritThreshold = 10
	cfg.EmailProtection.RateWindowMin = 10

	// Use a unique user per test to avoid sync.Map state collisions
	user := "rate-threshold-test@threshold.test"
	defer emailRateWindows.Delete(user)

	// Send 4 emails - no alert
	for i := 0; i < 4; i++ {
		findings := checkEmailRate(user, cfg)
		if len(findings) != 0 {
			t.Fatalf("expected no findings at count %d, got %d", i+1, len(findings))
		}
	}

	// 5th email - warn threshold
	findings := checkEmailRate(user, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding at warn threshold, got %d", len(findings))
	}
	if findings[0].Check != "email_rate_warning" {
		t.Errorf("expected check email_rate_warning, got %s", findings[0].Check)
	}

	// 6th-9th - no new alert (already alerted for warn)
	for i := 6; i <= 9; i++ {
		dedupFindings := checkEmailRate(user, cfg)
		if len(dedupFindings) != 0 {
			t.Fatalf("expected no findings at count %d (dedup), got %d", i, len(dedupFindings))
		}
	}

	// 10th email - critical threshold
	findings = checkEmailRate(user, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding at crit threshold, got %d", len(findings))
	}
	if findings[0].Check != "email_rate_critical" {
		t.Errorf("expected check email_rate_critical, got %s", findings[0].Check)
	}

	// 11th email - no new alert (already alerted for crit)
	findings = checkEmailRate(user, cfg)
	if len(findings) != 0 {
		t.Fatalf("expected no findings after crit dedup, got %d", len(findings))
	}
}
