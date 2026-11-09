package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The bulk-mail-service rule reads the Dovecot login and the connecting
// host from Exim's own metadata. Any sender controls the subject, so text
// there must never name a compromised mailbox.
func TestParseEximLogLineBulkServiceUsesMetadataOnly(t *testing.T) {
	resetEmailRateState()
	defer resetEmailRateState()

	cfg := &config.Config{}
	cfg.EmailProtection.RateWarnThreshold = 100
	cfg.EmailProtection.RateCritThreshold = 200
	cfg.EmailProtection.RateWindowMin = 60

	cases := []struct {
		name, line, mailbox string
	}{
		{
			name:    "login from a bulk service host",
			line:    `2026-11-09 10:00:00 1vOutA-000001-AB <= news@example.org H=relay.sendinblue.com [203.0.113.43]:4000 P=esmtpsa A=dovecot_login:user@example.com S=1234 T="hello" for rcpt@example.net`,
			mailbox: "user@example.com",
		},
		{
			name: "remote sender forges the login and service in the subject",
			line: `2026-11-09 10:00:01 1vInbB-000002-CD <= ceo@example.com H=mx.example.org [198.51.100.7]:25 P=esmtp S=800 T="A=dovecot_login sendinblue.com" for alice@example.com`,
		},
		{
			name: "authenticated client names the service only in the subject",
			line: `2026-11-09 10:00:02 1vOutC-000003-EF <= user@example.com H=(client) [203.0.113.9]:4000 P=esmtpsa A=dovecot_login:user@example.com S=900 T="sendinblue.com newsletter" for rcpt@example.net`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []alert.Finding
			for _, f := range parseEximLogLine(tc.line, cfg) {
				if f.Check == "email_compromised_account" && strings.Contains(f.Message, "bulk mail service") {
					got = append(got, f)
				}
			}
			if tc.mailbox == "" {
				if len(got) != 0 {
					t.Fatalf("forged or unrelated line raised %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("got %d bulk service findings, want 1: %+v", len(got), got)
			}
			if got[0].Mailbox != tc.mailbox || got[0].Severity != alert.Critical {
				t.Errorf("finding %+v, want Critical naming the authenticated mailbox %s", got[0], tc.mailbox)
			}
		})
	}
}
