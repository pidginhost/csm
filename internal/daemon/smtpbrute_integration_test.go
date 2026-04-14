package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// makeEximDovecotFailLine returns a synthetic exim mainlog line with the
// dovecot_login authenticator-failed format.
func makeEximDovecotFailLine(ip, account string) string {
	return fmt.Sprintf(
		"2026-04-14 12:00:00 dovecot_login authenticator failed for H=(bot.example) [%s]:54321: 535 Incorrect authentication data (set_id=%s)",
		ip, account,
	)
}

// buildEximHandler mirrors the closure the daemon installs at runtime,
// so tests can exercise the same code path without spinning up a daemon.
func buildEximHandler(cfg *config.Config, tr *smtpAuthTracker) LogLineHandler {
	return func(line string, c *config.Config) []alert.Finding {
		findings := parseEximLogLine(line, c)
		if strings.Contains(line, "authenticator failed") && strings.Contains(line, "dovecot") {
			ip := extractBracketedIP(line)
			account := extractSetID(line)
			if tr != nil && ip != "" && !isInfraIPDaemon(ip, c.InfraIPs) && !isPrivateOrLoopback(ip) {
				findings = append(findings, tr.Record(ip, account)...)
			}
		}
		return findings
	}
}

func TestEximHandler_NilTrackerSafe(t *testing.T) {
	cfg := &config.Config{}
	h := buildEximHandler(cfg, nil)
	out := h(makeEximDovecotFailLine("203.0.113.5", "alice@example.com"), cfg)
	for _, f := range out {
		if f.Check == "smtp_bruteforce" || f.Check == "smtp_subnet_spray" || f.Check == "smtp_account_spray" {
			t.Fatalf("nil tracker must not emit SMTP tracker findings: %v", out)
		}
	}
}

func TestEximHandler_SMTPBruteForce_EmitsFindingAtThreshold(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.SMTPBruteForceThreshold = 5
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	h := buildEximHandler(cfg, tr)
	var fired bool
	for i := 0; i < 5; i++ {
		for _, f := range h(makeEximDovecotFailLine("203.0.113.5", "alice@example.com"), cfg) {
			if f.Check == "smtp_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("expected smtp_bruteforce finding at 5th record")
	}
}

func TestEximHandler_SMTPBruteForce_EmailAuthFailureStillEmitted(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.SMTPBruteForceThreshold = 5
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	h := buildEximHandler(cfg, tr)
	out := h(makeEximDovecotFailLine("203.0.113.5", "alice@example.com"), cfg)
	var sawRealtime bool
	for _, f := range out {
		if f.Check == "email_auth_failure_realtime" {
			sawRealtime = true
		}
	}
	if !sawRealtime {
		t.Errorf("email_auth_failure_realtime must still fire; findings=%v", out)
	}
}

func TestEximHandler_SMTPBruteForce_InfraIPIgnored(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"203.0.113.5"}}
	cfg.Thresholds.SMTPBruteForceThreshold = 5
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	h := buildEximHandler(cfg, tr)
	for i := 0; i < 20; i++ {
		for _, f := range h(makeEximDovecotFailLine("203.0.113.5", "alice@example.com"), cfg) {
			if f.Check == "smtp_bruteforce" {
				t.Fatalf("infra IP must never trigger smtp_bruteforce")
			}
		}
	}
}

func TestEximHandler_SMTPSubnetSpray(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.SMTPBruteForceThreshold = 5
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	h := buildEximHandler(cfg, tr)
	var fired bool
	for i := 1; i <= 8; i++ {
		line := makeEximDovecotFailLine(fmt.Sprintf("203.0.113.%d", i), "alice@example.com")
		for _, f := range h(line, cfg) {
			if f.Check == "smtp_subnet_spray" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("expected smtp_subnet_spray after 8 unique IPs in /24")
	}
}
