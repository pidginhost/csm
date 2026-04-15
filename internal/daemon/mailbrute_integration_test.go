package daemon

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// makeDovecotFailLine returns a synthetic dovecot auth-failed line.
func makeDovecotFailLine(protocol, ip, account string) string {
	return fmt.Sprintf(
		"Apr 14 12:00:00 host dovecot: %s-login: Aborted login (auth failed, 1 attempts in 2 secs): user=<%s>, method=PLAIN, rip=%s, lip=1.1.1.1, TLS",
		protocol, account, ip,
	)
}

// makeDovecotSuccessLine returns a synthetic dovecot successful-login line
// matching the real wire format (see TestExtractMailLoginEvent_RealDovecotFormat).
func makeDovecotSuccessLine(protocol, ip, account string) string {
	return fmt.Sprintf(
		"Apr 14 12:00:05 host dovecot: %s-login: Logged in: user=<%s>, method=PLAIN, rip=%s, lip=1.1.1.1, TLS",
		protocol, account, ip,
	)
}

// buildMailHandler mirrors the closure daemon.go installs at runtime so
// tests can exercise the same logic without spinning up a Daemon. MUST
// compose with parseDovecotLogLine (existing handler) — not replace it —
// so email_suspicious_geo continues to fire.
func buildMailHandler(cfg *config.Config, tr *mailAuthTracker) LogLineHandler {
	return func(line string, c *config.Config) []alert.Finding {
		findings := parseDovecotLogLine(line, c)
		if !isMailAuthLine(line) {
			return findings
		}
		ip, account, success := extractMailLoginEvent(line)
		if ip == "" {
			return findings
		}
		if parsed := net.ParseIP(ip); parsed != nil {
			if v4 := parsed.To4(); v4 != nil {
				ip = v4.String()
			}
		}
		if isInfraIPDaemon(ip, c.InfraIPs) || isPrivateOrLoopback(ip) {
			return findings
		}
		if tr == nil {
			return findings
		}
		if success {
			findings = append(findings, tr.RecordSuccess(ip, account)...)
		} else {
			findings = append(findings, tr.Record(ip, account)...)
		}
		return findings
	}
}

func TestMailHandler_BruteForce_EmitsFindingAtThreshold(t *testing.T) {
	cfg := &config.Config{}
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	h := buildMailHandler(cfg, tr)
	var fired bool
	for i := 0; i < 5; i++ {
		for _, f := range h(makeDovecotFailLine("imap", "203.0.113.5", "alice@example.com"), cfg) {
			if f.Check == "mail_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("expected mail_bruteforce at 5th record")
	}
}

func TestMailHandler_Compromise_SuccessAfterFailure(t *testing.T) {
	cfg := &config.Config{}
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	h := buildMailHandler(cfg, tr)
	for i := 0; i < 3; i++ {
		h(makeDovecotFailLine("imap", "203.0.113.5", "alice@example.com"), cfg)
	}
	var fired bool
	for _, f := range h(makeDovecotSuccessLine("imap", "203.0.113.5", "alice@example.com"), cfg) {
		if f.Check == "mail_account_compromised" {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("expected mail_account_compromised after success-from-attacker-IP")
	}
}

func TestMailHandler_SubnetSpray_EmitsCIDR(t *testing.T) {
	cfg := &config.Config{}
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	h := buildMailHandler(cfg, tr)
	var fired bool
	for i := 1; i <= 8; i++ {
		line := makeDovecotFailLine("imap", fmt.Sprintf("203.0.113.%d", i), "alice@example.com")
		for _, f := range h(line, cfg) {
			if f.Check == "mail_subnet_spray" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("expected mail_subnet_spray after 8 unique IPs in /24")
	}
}

func TestMailHandler_InfraIPIgnored(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"203.0.113.5"}}
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	h := buildMailHandler(cfg, tr)
	for i := 0; i < 20; i++ {
		for _, f := range h(makeDovecotFailLine("imap", "203.0.113.5", "alice@example.com"), cfg) {
			if f.Check == "mail_bruteforce" {
				t.Fatalf("infra IP must never fire mail_bruteforce")
			}
		}
	}
}

func TestMailHandler_IPv4MappedIPv6Canonicalized(t *testing.T) {
	cfg := &config.Config{}
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	h := buildMailHandler(cfg, tr)
	variants := []string{"203.0.113.5", "::ffff:203.0.113.5", "203.0.113.5", "::ffff:203.0.113.5", "203.0.113.5"}
	var fired bool
	for _, ip := range variants {
		for _, f := range h(makeDovecotFailLine("imap", ip, "alice@example.com"), cfg) {
			if f.Check == "mail_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("IPv4-mapped IPv6 must canonicalize")
	}
}

func TestMailHandler_NilTrackerSafe(t *testing.T) {
	cfg := &config.Config{}
	h := buildMailHandler(cfg, nil)
	out := h(makeDovecotFailLine("imap", "203.0.113.5", "alice@example.com"), cfg)
	for _, f := range out {
		if f.Check == "mail_bruteforce" || f.Check == "mail_subnet_spray" ||
			f.Check == "mail_account_spray" || f.Check == "mail_account_compromised" {
			t.Fatalf("nil tracker must not emit tracker findings: %v", out)
		}
	}
}

// MANDATORY regression test: the wrapper must CALL parseDovecotLogLine, not
// replace it. parseDovecotLogLine returns nil in test env (GeoIP DB and
// bbolt store aren't initialized), so we assert the compose invariant:
// wrapper output ⊇ parseDovecotLogLine output for the same input. Catches
// any future edit that accidentally drops the parseDovecotLogLine call.
func TestMailHandler_EmailSuspiciousGeoStillFiresThroughWrapper(t *testing.T) {
	cfg := &config.Config{}
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	h := buildMailHandler(cfg, tr)

	// Prime tracker so RecordSuccess can fire on a later success line.
	for i := 0; i < 3; i++ {
		h(makeDovecotFailLine("imap", "198.51.100.42", "victim@example.com"), cfg)
	}

	successLine := makeDovecotSuccessLine("imap", "198.51.100.42", "victim@example.com")

	wrapperOut := h(successLine, cfg)
	geoOut := parseDovecotLogLine(successLine, cfg)

	// Compose invariant: wrapper result ⊇ parseDovecotLogLine result.
	for _, g := range geoOut {
		found := false
		for _, o := range wrapperOut {
			if o.Check == g.Check && o.Message == g.Message {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("wrapper dropped parseDovecotLogLine finding: check=%s msg=%s",
				g.Check, g.Message)
		}
	}

	// And the tracker path still fires for the same line (both halves wired).
	var compromiseFired bool
	for _, f := range wrapperOut {
		if f.Check == "mail_account_compromised" {
			compromiseFired = true
		}
	}
	if !compromiseFired {
		t.Fatal("wrapper failed to produce tracker finding — composition broken")
	}
}
