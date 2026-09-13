package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestMailVolumeAttributesVerifiedSubmitter(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	withOwnerTable(t)
	for _, tc := range []struct{ name, fields, owner string }{
		{"authenticated mailbox", "H=mail.example.org [203.0.113.5] P=esmtpsa A=dovecot_login:user@example.net S=100", "bob"},
		{"bare authenticated account", "H=mail.example.org [203.0.113.5] P=esmtpsa A=dovecot_plain:bob S=100", "bob"},
		{"local submission", "U=bob P=local S=100", "bob"},
		{"local message id with host text", `U=bob P=local S=100 id="note H=mail.example"@example.org`, "bob"},
		{"local message id with auth text", `U=bob P=local S=100 id=part." A=dovecot_login:user@example.com "@example.org`, "bob"},
		{"remote message id with auth text", `H=mail.example.org [203.0.113.5] P=esmtp S=100 id=part." A=dovecot_login:user@example.net "@example.org`, ""},
		{"remote ident is not local", "H=mail.example.org [203.0.113.5] U=bob P=esmtp S=100", ""},
		{"remote ident cannot forge auth", "H=mail.example.org [203.0.113.5] U=remote A=dovecot_login:user@example.net P=esmtp S=100", ""},
		{"remote ident cannot forge reception metadata", "H=mail.example.org [203.0.113.5] U=remote P=esmtpsa A=dovecot_login:user@example.net S=100 P=esmtp S=200", ""},
		{"helo cannot hide remote ident", "H=(hello() [203.0.113.5] U=) [192.0.2.8] P=esmtpsa A=dovecot_login:user@example.net S=100 P=esmtp S=200", ""},
		{"helo cannot forge metadata before ident", `H=(hello) [192.0.2.8] P=esmtpsa A=dovecot_login:user@example.net S=100 T=") [203.0.113.5] U=" P=esmtp S=200`, ""},
		{"system submission", "U=nobody P=local S=100", ""},
		{"unknown submission", "U=ghost P=local S=100", ""},
		{"unknown mailbox", "H=mail.example.org [203.0.113.5] P=esmtpsa A=dovecot_login:user@example.org S=100", ""},
		{"empty mailbox user", "H=mail.example.org [203.0.113.5] P=esmtpsa A=dovecot_login:@example.net S=100", ""},
		{"ambiguous mailbox", "H=mail.example.org [203.0.113.5] P=esmtpsa A=dovecot_login:user@example.com@example.net S=100", ""},
		{"forged helo", "H=(P=local U=bob A=dovecot_login:user@example.net) [203.0.113.5] P=esmtp S=100", ""},
		{"forged subject", `H=mail.example.org [203.0.113.5] P=esmtp S=100 T="P=local U=bob A=dovecot_login:user@example.net"`, ""},
		{"forged quoted field", `H=mail.example.org [203.0.113.5] X="A=dovecot_login:user@example.net" P=esmtp S=100`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := "2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com " + tc.fields + "\n"
			withMockOS(t, &mockOS{open: openTempLog(t, strings.Repeat(line, perAccountMailThreshold))})
			got := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
			if len(got) != 1 || got[0].Severity != alert.High || got[0].Domain != "example.com" {
				t.Fatalf("volume detection changed: %+v", got)
			}
			if got[0].TenantID != tc.owner || extractAccountFromFinding(got[0]) != tc.owner {
				t.Fatalf("owner %q, correlation owner %q, want verified submitter %q", got[0].TenantID, extractAccountFromFinding(got[0]), tc.owner)
			}
		})
	}
}

func TestMailVolumeRequiresOneOwnerForEntireAggregate(t *testing.T) {
	withOwnerTable(t)
	line := func(auth string) string {
		return "2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=mail.example.org [203.0.113.5] P=esmtpsa " + auth + " S=100\n"
	}
	for _, auth := range []string{"", "A=dovecot_login:user@example.com", "A=dovecot_login:user@example.org"} {
		for _, first := range []bool{false, true} {
			body := strings.Repeat(line("A=dovecot_login:user@example.net"), perAccountMailThreshold-1)
			if first {
				body = line(auth) + body
			} else {
				body += line(auth)
			}
			withMockOS(t, &mockOS{open: openTempLog(t, body)})
			got := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
			if len(got) != 1 || got[0].TenantID != "" || extractAccountFromFinding(got[0]) != "" {
				t.Fatalf("mixed aggregate acquired an owner: %+v", got)
			}
		}
	}
}

func TestMailVolumeOwnerChangeHasDistinctFindingIdentity(t *testing.T) {
	withOwnerTable(t)
	var got []alert.Finding
	for _, mailbox := range []string{"user@example.com", "user@example.net", "user@example.com"} {
		line := "2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.org H=mail.example.org [203.0.113.5] P=esmtpsa A=dovecot_login:" + mailbox + " S=100\n"
		withMockOS(t, &mockOS{open: openTempLog(t, strings.Repeat(line, perAccountMailThreshold))})
		got = append(got, CheckMailPerAccount(context.Background(), &config.Config{}, nil)...)
	}
	if len(alert.Deduplicate(got)) != 2 || alert.FindingID(got[0]) == alert.FindingID(got[1]) {
		t.Fatalf("different submitting accounts collapsed into one identity: %+v", got)
	}
}
