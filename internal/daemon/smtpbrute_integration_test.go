package daemon

import (
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// makeEximDovecotFailLine returns a synthetic exim mainlog line with the
// dovecot_login authenticator-failed format. Exim emits it via
// host_and_ident(FALSE), so there is no H= prefix: the HELO sits in
// parentheses directly before the connecting client.
func makeEximDovecotFailLine(ip, account string) string {
	return fmt.Sprintf(
		"2026-04-14 12:00:00 dovecot_login authenticator failed for (bot.example) [%s]:54321: 535 Incorrect authentication data (set_id=%s)",
		ip, account,
	)
}

// buildEximHandler runs the daemon's Exim line handler with tr as its SMTP
// tracker.
func buildEximHandler(cfg *config.Config, tr *smtpAuthTracker) LogLineHandler {
	d := New(cfg, nil, nil, "")
	d.smtpAuthTracker = tr
	return func(line string, c *config.Config) []alert.Finding {
		return d.handleEximLine(line, alert.Observation{}, c)
	}
}

// newTestTrackerWithSpray is newTestTracker feeding a spray memory that
// records failures and login trust but emits no spray verdicts.
func newTestTrackerWithSpray(t *testing.T, clock *staticClock) *smtpAuthTracker {
	t.Helper()
	tr := newTestTracker(t, clock)
	tr.SetSpray(newMailSpray(sprayConfig{Mode: sprayOff, Window: 7 * 24 * time.Hour, TrustAge: 10 * time.Minute, Suppression: time.Hour, MaxIPs: 20000}, clock.Now))
	return tr
}

// trustedPairs lists the (address, mailbox) pairs holding login trust.
func trustedPairs(tr *smtpAuthTracker) map[sprayTrustKey]bool {
	tr.spray.mu.Lock()
	defer tr.spray.mu.Unlock()
	out := map[sprayTrustKey]bool{}
	for k := range tr.spray.trust {
		out[k] = true
	}
	return out
}

func makeEximDovecotSuccessLine(clientIP string) string {
	return fmt.Sprintf(
		`2026-04-14 12:00:00 1abc-DEF-01 <= sender@example.com H=([192.0.2.94]) [%s]:54321 P=esmtpsa A=dovecot_login:sender@example.com S=1200 T="forwarded [203.0.113.77]"`,
		clientIP,
	)
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

func TestEximHandler_IPv4MappedIPv6Canonicalized(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.SMTPBruteForceThreshold = 5
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	h := buildEximHandler(cfg, tr)

	// Interleave raw IPv4 and IPv4-mapped IPv6 for the same attacker.
	// If not canonicalized, each half-count falls below threshold.
	variants := []string{"203.0.113.5", "::ffff:203.0.113.5", "203.0.113.5", "::ffff:203.0.113.5", "203.0.113.5"}
	var fired bool
	for _, ip := range variants {
		for _, f := range h(makeEximDovecotFailLine(ip, "alice@example.com"), cfg) {
			if f.Check == "smtp_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("IPv4-mapped IPv6 must canonicalize so all five records count as one IP at threshold")
	}
}

func TestEximHandler_SMTPAuthSuccessUsesHFieldClientIP(t *testing.T) {
	cfg := &config.Config{}
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTrackerWithSpray(t, clock)
	h := buildEximHandler(cfg, tr)

	h(makeEximDovecotSuccessLine("198.51.100.92"), cfg)
	want := map[sprayTrustKey]bool{{"198.51.100.92", "sender@example.com"}: true}
	if got := trustedPairs(tr); !maps.Equal(got, want) {
		t.Fatalf("login trust = %v, want only the H=[client] address %v (not the HELO or subject address)", got, want)
	}
}

func TestEximHandler_SubjectCannotSpoofSMTPAuthSuccess(t *testing.T) {
	cfg := &config.Config{}
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTrackerWithSpray(t, clock)
	h := buildEximHandler(cfg, tr)
	line := `2026-04-14 12:00:00 1abc-DEF-01 <= sender@example.net H=attacker.example [198.51.100.93]:54321 P=esmtp S=1200 T="A=dovecot_login:forged@example.net"`

	h(line, cfg)
	if got := trustedPairs(tr); len(got) != 0 {
		t.Fatalf("attacker-controlled subject was accepted as an SMTP auth success: %v", got)
	}
}

func TestEximHandler_SMTPAuthSuccessRequiresHFieldClientIP(t *testing.T) {
	cfg := &config.Config{}
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTrackerWithSpray(t, clock)
	h := buildEximHandler(cfg, tr)
	line := `2026-04-14 12:00:00 1abc-DEF-01 <= sender@example.net P=esmtpsa A=dovecot_login:sender@example.net S=1200 T="forwarded [198.51.100.94]"`

	h(line, cfg)
	if got, trust := tr.Size(), trustedPairs(tr); got != 0 || len(trust) != 0 {
		t.Fatalf("authenticated line without H=[client] recorded a subject/header address: size=%d trust=%v", got, trust)
	}
}
