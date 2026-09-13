package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Text that imitates a logged peer and remote ident. Senders choose it for
// subjects and addresses, and connecting clients choose it as a login name.
const eximPeerLikeText = `[192.0.2.1]:25 U=x`

func TestAuthFailureLoginTextKeepsSourceIP(t *testing.T) {
	line := `2026-01-01 10:00:00 dovecot_login authenticator failed for (helo.example) [203.0.113.5]:2525: 535 Incorrect authentication data (set_id=` + eximPeerLikeText + `)`
	for _, f := range parseEximLogLine(line, testEmailProtectionConfig()) {
		if f.Check == "email_auth_failure_realtime" {
			if f.SourceIP != "203.0.113.5" {
				t.Fatalf("SourceIP = %q, want 203.0.113.5", f.SourceIP)
			}
			return
		}
	}
	t.Fatal("authentication failure was not reported")
}

func TestAuthenticatedRateCountsSubjectWithPeerText(t *testing.T) {
	withOwnerTable(t)
	resetEmailRateState()
	t.Cleanup(resetEmailRateState)
	line := `2026-01-01 10:00:00 1abc23-000456-AB <= user@example.com H=mail.example (helo.example) [203.0.113.5]:2525 P=esmtpsa A=dovecot_login:user@example.com S=100 id=x@example.com T="` + eximPeerLikeText + `" for user@example.org`
	var findings []alert.Finding
	for i := 0; i < 3; i++ {
		findings = append(findings, parseEximLogLine(line, testEmailProtectionConfig())...)
	}
	requireOwner(t, findings, "email_rate_critical", "alice")
	for _, f := range findings {
		if f.Check == "email_rate_critical" {
			return
		}
	}
	t.Fatalf("authenticated sends were not counted: %+v", findings)
}

func TestCloudRelayCountsRecipientWithPeerText(t *testing.T) {
	resetCloudRelayState()
	t.Cleanup(resetCloudRelayState)
	cfg := cloudRelayTestConfig()
	for _, ip := range []string{"203.0.113.10", "203.0.113.11", "203.0.113.12"} {
		line := "2026-04-22 14:00:00 1abc-0000-AB <= info@example.com H=host.bc.googleusercontent.com (helo.example) [" + ip + "]:44948 P=esmtpsa A=dovecot_plain:info@example.com S=100 id=x@example.com T=\"hello\" for \"" + eximPeerLikeText + "\"@example.org"
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check == "email_cloud_relay_abuse" {
				return
			}
		}
	}
	t.Fatal("cloud relay sends with peer-like recipient text were not counted")
}
