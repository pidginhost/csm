package daemon

import (
	"strings"
	"testing"
)

func TestParseDKIMFailure(t *testing.T) {
	tests := []struct {
		line   string
		domain string
	}{
		{"2026-04-04 10:00:00 DKIM: signing failed for example.com: no key", "example.com"},
		{"2026-04-04 10:00:00 DKIM: signing failed for sub.domain.org: DNS lookup error", "sub.domain.org"},
		{"2026-04-04 10:00:00 normal log line without DKIM failure", ""},
		{"2026-04-04 10:00:00 DKIM: d=example.com s=selector verified OK", ""},
	}
	for _, tt := range tests {
		got := parseDKIMFailureDomain(tt.line)
		if got != tt.domain {
			t.Errorf("parseDKIMFailureDomain(%q) = %q, want %q", tt.line, got, tt.domain)
		}
	}
}

func TestParseSPFDMARCRejection(t *testing.T) {
	tests := []struct {
		name         string
		line         string
		senderDomain string
		reasonPrefix string
	}{
		{
			"SPF PTR record failure",
			`2026-03-29 09:44:28 1w6jso-0000000G1zB-1Jus ** sender@gmail.com (info@example.org) <info@example.org> R=dkim_lookuphost T=dkim_remote_smtp H=gmail-smtp-in.l.google.com [142.250.110.26] : SMTP error from remote mail server after end of data: 550-5.7.25 [203.0.113.193] The IP address sending this message does not have a PTR record`,
			"example.org",
			"SMTP error from remote mail server",
		},
		{
			"DMARC policy rejection",
			`2026-04-04 10:15:23 1abc23-000456-AB ** user@example.com (office@sender.com) <office@sender.com> R=dkim_lookuphost : 550 5.7.26 This message does not have authentication`,
			"sender.com",
			"550 5.7.26",
		},
		{
			"Gmail spam with SPF keyword",
			`2026-03-29 08:22:58 1w6ibx ** robert@gmail.com (contact@example.net) <contact@example.net> R=dkim_lookuphost : 550-5.7.1 Gmail has detected this message is spam. SPF check failed.`,
			"example.net",
			"550-5.7.1",
		},
		{
			"Successful delivery",
			`2026-04-04 10:15:23 1abc23 => user@example.com R=lookuphost T=remote_smtp`,
			"", "",
		},
		{
			"Non-SPF rejection",
			`2026-04-04 10:15:23 1abc23 ** user@example.com <sender@domain.com> : 550 5.1.1 Mailbox not found`,
			"", "",
		},
		{
			"No envelope sender",
			`2026-04-04 10:15:23 1abc23 ** admin@example.net R=virtual_aliases :`,
			"", "",
		},
		{
			"Generic 5.7.1 without SPF/DMARC keywords",
			`2026-04-04 10:15:23 1abc23 ** user@x.com <sender@test.com> : 550 5.7.1 Relaying denied`,
			"", "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, reason := parseSPFDMARCRejection(tt.line)
			if domain != tt.senderDomain {
				t.Errorf("domain = %q, want %q", domain, tt.senderDomain)
			}
			if tt.reasonPrefix != "" && !strings.HasPrefix(reason, tt.reasonPrefix) {
				t.Errorf("reason = %q, want prefix %q", reason, tt.reasonPrefix)
			}
			if tt.senderDomain == "" && reason != "" {
				t.Errorf("reason should be empty when domain is empty, got %q", reason)
			}
		})
	}
}

func TestIsSPFDMARCRelated(t *testing.T) {
	tests := []struct {
		reason  string
		related bool
	}{
		{"550 5.7.23 SPF validation failed", true},
		{"DMARC policy rejection", true},
		{"550 5.7.25 does not pass DMARC", true},
		{"550 5.7.26 fails authentication checks", true},
		{"SPF check failed", true},
		{"dkim alignment failure", true},
		{"550 5.7.1 Relaying denied", false},
		{"550 5.7.1 Message rejected content", false},
		{"550 5.1.1 Mailbox not found", false},
		{"Connection timed out", false},
		{"", false},
		{"550 5.7.1 PTR record missing SPF fails", true}, // 5.7.1 with SPF keyword
	}
	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			got := isSPFDMARCRelated(tt.reason)
			if got != tt.related {
				t.Errorf("isSPFDMARCRelated(%q) = %v, want %v", tt.reason, got, tt.related)
			}
		})
	}
}
