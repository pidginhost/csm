package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// Exim writes the authenticator-failed line through host_and_ident(FALSE),
// so there is no H= field: the client appears as "(HELO) [IP]:port". The HELO
// is attacker-controlled and may be an RFC 5321 address literal, which must not
// be mistaken for the connecting client.
func TestDaemonExtractBracketedIP_AuthFailureSkipsHELOAddressLiteral(t *testing.T) {
	line := `2026-04-14 12:00:00 dovecot_login authenticator failed for ([203.0.113.9]) [198.51.100.7]:5432: 535 Incorrect authentication data (set_id=alice@example.com)`
	if got := extractBracketedIP(line); got != "198.51.100.7" {
		t.Errorf("extractBracketedIP = %q, want the connecting client 198.51.100.7, not the HELO literal", got)
	}
}

func TestDaemonExtractBracketedIP_AuthFailureWithRDNSSkipsHELOAddressLiteral(t *testing.T) {
	line := `2026-04-14 12:00:00 dovecot_login authenticator failed for mail.example.net ([203.0.113.9]) [198.51.100.7]:5432: 535 Incorrect authentication data (set_id=alice@example.com)`
	if got := extractBracketedIP(line); got != "198.51.100.7" {
		t.Errorf("extractBracketedIP = %q, want 198.51.100.7", got)
	}
}

func TestDaemonExtractBracketedIP_AuthFailureSkipsIPv6HELOLiteral(t *testing.T) {
	line := `2026-04-14 12:00:00 dovecot_login authenticator failed for ([2001:db8::9]) [198.51.100.7]:5432: 535 Incorrect authentication data (set_id=alice@example.com)`
	if got := extractBracketedIP(line); got != "198.51.100.7" {
		t.Errorf("extractBracketedIP = %q, want 198.51.100.7", got)
	}
}

func TestDaemonExtractBracketedIP_TLSErrorSkipsHELOAddressLiteral(t *testing.T) {
	line := `2026-04-14 12:00:00 TLS error on connection from ([203.0.113.9]) [198.51.100.7]:5432 (SSL_accept): error:0A000126:SSL routines::unexpected eof while reading`
	if got := extractBracketedIP(line); got != "198.51.100.7" {
		t.Errorf("extractBracketedIP = %q, want 198.51.100.7", got)
	}
}

// makeEximDovecotFailLineWithHELO mirrors the production line shape exactly:
// no H= prefix, attacker-chosen HELO in parentheses before the client.
func makeEximDovecotFailLineWithHELO(helo, ip, account string) string {
	return fmt.Sprintf(
		"2026-04-14 12:00:00 dovecot_login authenticator failed for (%s) [%s]:54321: 535 Incorrect authentication data (set_id=%s)",
		helo, ip, account,
	)
}

// An attacker who sends "EHLO [203.0.113.9]" must not be able to steer the
// brute-force tracker (and therefore the firewall) at an IP of their choosing.
func TestEximHandler_SpoofedHELOAddressLiteralTracksRealClient(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.SMTPBruteForceThreshold = 5
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	h := buildEximHandler(cfg, tr)

	const forged, real = "203.0.113.9", "198.51.100.7"
	var sources []string
	for i := 0; i < 5; i++ {
		line := makeEximDovecotFailLineWithHELO("["+forged+"]", real, "alice@example.com")
		for _, f := range h(line, cfg) {
			if f.Check == "smtp_bruteforce" {
				sources = append(sources, f.SourceIP)
			}
		}
	}
	if len(sources) != 1 {
		t.Fatalf("expected exactly one smtp_bruteforce finding, got %d: %v", len(sources), sources)
	}
	if sources[0] != real {
		t.Fatalf("smtp_bruteforce SourceIP = %q, want the connecting client %q (forged HELO literal %q must be ignored)", sources[0], real, forged)
	}
}
