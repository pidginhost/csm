package eximlog

import (
	"strings"
	"testing"
)

func TestSubmitterUsesArrivalMetadata(t *testing.T) {
	for _, tc := range []struct{ name, prefix, fields, want string }{
		{"authenticated", "2026-01-01 10:00:00", "H=mail.example [203.0.113.5]:2525 P=esmtpsa A=dovecot_login:bob@example.net S=100", "bob@example.net"},
		{"apostrophe in mailbox", "2026-01-01 10:00:00", "H=mail.example [203.0.113.5] P=esmtpsa A=dovecot_login:o'brien@example.net S=100", "o'brien@example.net"},
		{"local", "2026-01-01 10:00:00", "U=bob P=local S=100", "bob"},
		{"milliseconds zone pid", "2026-01-01 10:00:00.123 +0200 [1234]", "U=bob P=local S=100", "bob"},
		{"smtp mailauth", "2026-01-01 10:00:00", "H=mail.example [203.0.113.5] P=esmtpsa A=dovecot_plain:bob@example.net:other@example.com S=100", "bob@example.net"},
		{"remote ident", "2026-01-01 10:00:00", "H=mail.example [203.0.113.5] U=bob P=esmtp S=100", ""},
		{"remote local protocol", "2026-01-01 10:00:00", "H=mail.example [203.0.113.5] U=bob P=local S=100", ""},
		{"ambiguous auth", "2026-01-01 10:00:00", "A=dovecot_login:bob@example.net A=dovecot_plain:alice@example.com S=100", ""},
		{"ambiguous user", "2026-01-01 10:00:00", "U=bob U=alice P=local S=100", ""},
		{"ambiguous protocol", "2026-01-01 10:00:00", "U=bob P=local P=esmtp S=100", ""},
		{"unknown auth no local fallback", "2026-01-01 10:00:00", "U=bob P=local A=unknown:user S=100", ""},
		{"subject", "2026-01-01 10:00:00", `P=esmtp T="A=dovecot_login:bob@example.net U=bob P=local"`, ""},
		{"recipients", "2026-01-01 10:00:00", "P=esmtp S=100 for A=dovecot_login:bob@example.net", ""},
		{"malformed peer", "2026-01-01 10:00:00", "H=(bad [203.0.113.5] P=esmtpsa A=dovecot_login:bob@example.net", ""},
		{"missing time", "2026-01-01", "U=bob P=local S=100", ""},
		{"invalid pid", "2026-01-01 10:00:00 [abc]", "U=bob P=local S=100", ""},
		{"embedded arrival", "2026-01-01 10:00:00 1abc23-000456-AB == recipient@example.com response", "A=dovecot_login:bob@example.net", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.prefix + " 1abc23-000456-AB <= sender@example.com " + tc.fields
			if got := Submitter(line); got != tc.want {
				t.Fatalf("submitter %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSubmitterSkipsQuotedEnvelope(t *testing.T) {
	for _, sender := range []string{`"name A=dovecot_login:forged@example.net"@example.com`, `"name \\\" A=dovecot_login:forged@example.net"@example.com`} {
		line := "2026-01-01 10:00:00 1abc23-000456-AB <= " + sender + " U=bob P=local S=100"
		if got := Submitter(line); got != "bob" {
			t.Fatalf("quoted envelope produced submitter %q, want local caller bob", got)
		}
	}
}

func FuzzSubmitter(f *testing.F) {
	f.Add("2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com U=bob P=local S=100")
	f.Add("2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=(odd) [203.0.113.5] A=dovecot_login:bob@example.net S=100")
	f.Fuzz(func(t *testing.T, line string) {
		got := Submitter(line)
		if got != "" && !strings.Contains(line, got) {
			t.Fatalf("submitter %q has no source in the log record", got)
		}
	})
}
