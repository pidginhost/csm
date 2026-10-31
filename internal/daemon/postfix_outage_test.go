package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A silent xsasl_dovecot_server_connect failure leaves the previous reply
// untouched. Neither that text nor the cached username proves a rejection.
func TestPostfixSilentHandshakeFailureDoesNotBuildEvidence(t *testing.T) {
	for _, reply := range []string{
		"", "(reason unavailable)", "UGFzc3dvcmQ6", "authentication failure",
		"Invalid base64 data in initial response",
		"Invalid authentication mechanism: 'UNKNOWN'",
	} {
		for _, suffix := range []string{"", ", sasl_username=alice@example.net"} {
			t.Run(reply+suffix, func(t *testing.T) {
				clock := &staticClock{t: time.Unix(1_700_000_000, 0)}
				d := New(&config.Config{}, nil, nil, "")
				d.smtpAuthTracker = newTestTracker(t, clock)
				// A reachable socket does not prove a working auth handshake.
				d.smtpAuthTracker.SetBackendDownCheck(func() bool { return false })
				for client := 1; client <= 10; client++ {
					for attempt := 0; attempt < 10; attempt++ {
						line := fmt.Sprintf("postfix/smtpd[%d]: warning: unknown[203.0.113.%d]: SASL PLAIN authentication failed: %s%s", client, client, reply, suffix)
						if got := d.handleMailLine(line, alert.Observation{}, d.currentCfg()); len(got) != 0 {
							t.Fatalf("silent backend outage raised findings: %+v", got)
						}
					}
				}
				if calls, emits := d.smtpAuthTracker.Stats(); calls != 0 || emits != 0 || d.smtpAuthTracker.Size() != 0 {
					t.Fatalf("silent outage left evidence: calls=%d emits=%d entries=%d", calls, emits, d.smtpAuthTracker.Size())
				}
			})
		}
	}
}

func TestPostfixWarningsDoNotAffectOtherMailDetection(t *testing.T) {
	clock := &staticClock{t: time.Unix(1_700_000_000, 0)}
	d := New(&config.Config{}, nil, nil, "")
	d.smtpAuthTracker = newTestTracker(t, clock)
	d.mailAuthTracker = newTestMailTracker(t, clock)
	for _, diagnostic := range []string{
		"SASL: Connect to Dovecot auth socket 'private/auth' failed: Connection refused",
		"SASL: Couldn't send handshake: Broken pipe",
		"SASL: Protocol version error",
		"SASL: Protocol version mismatch (2 vs. 1)",
		"SASL: Connected to wrong auth socket (auth-master instead of auth-client)",
	} {
		for i := 0; i < 10; i++ {
			for _, msg := range []string{diagnostic, "unknown[203.0.113.61]: SASL PLAIN authentication failed: authentication failure"} {
				if got := d.handleMailLine("postfix/smtpd[99]: warning: "+msg, alert.Observation{}, d.currentCfg()); len(got) != 0 {
					t.Fatalf("backend outage raised findings: %+v", got)
				}
			}
		}
	}
	for _, tc := range []struct {
		line, check, immediate string
		handle                 ObservedLineHandler
	}{
		{"2026-01-01 12:00:00 dovecot_login authenticator failed for unknown [203.0.113.61]: 535 Incorrect authentication data (set_id=alice@example.net)", "smtp_bruteforce", "email_auth_failure_realtime", d.handleEximLine},
		{"dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<alice@example.net>, method=PLAIN, rip=203.0.113.61, lip=192.0.2.1", "mail_bruteforce", "", d.handleMailLine},
	} {
		for attempt := 1; attempt <= 5; attempt++ {
			got := tc.handle(tc.line, alert.Observation{}, d.currentCfg())
			var want []string
			if tc.immediate != "" {
				want = append(want, tc.immediate)
			}
			if attempt == 5 {
				want = append(want, tc.check)
			}
			if len(got) != len(want) {
				t.Fatalf("%s attempt %d: got %+v, want %v", tc.check, attempt, got, want)
			}
			for i, check := range want {
				if got[i].Check != check || got[i].SourceIP != "203.0.113.61" {
					t.Fatalf("%s attempt %d: finding %d = %+v, want %s for 203.0.113.61", tc.check, attempt, i, got[i], check)
				}
			}
		}
	}
}
