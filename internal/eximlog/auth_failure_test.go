package eximlog

import "testing"

func TestAuthFailureRecord(t *testing.T) {
	const client = "mail.example.com (set_id=decoy@example.com) [203.0.113.7]:54321 I=[192.0.2.25]:25 Ci=4711"
	for _, prefix := range []string{
		"", "2026-04-14 12:00:00 ", "2026-04-14 12:00:00.123 ",
		"2026-04-14 12:00:00 +0200 ", "2026-04-14 12:00:00 [123] ",
		"2026-04-14 12:00:00.123 +0200 [123] ",
	} {
		for _, code := range []string{"535", "435"} {
			line := prefix + "dovecot_plain authenticator failed for " + client + ": " + code + " Authentication failed (set_id=a@example.com)"
			want := AuthFailureRecord{Authenticator: "dovecot_plain", ClientIP: "203.0.113.7", Code: code, Account: "a@example.com"}
			if got := AuthFailure(line); got != want {
				t.Errorf("AuthFailure(%q) = %+v, want %+v", line, got, want)
			}
		}
	}
}

func TestAuthFailurePreservesCompleteAccount(t *testing.T) {
	for _, account := range []string{"a@example.com", "a@example.com extra", "a@example.com)extra", "a@example.com (set_id=b@example.com)"} {
		line := "dovecot_login authenticator failed for (mail.example.com) [203.0.113.7]: 535 Incorrect authentication data (set_id=" + account + ")"
		if got := AuthFailure(line); got.Account != account || got.ClientIP != "203.0.113.7" || got.Code != "535" {
			t.Fatalf("login text changed the failure record: %+v", got)
		}
	}
}

func TestAuthFailureUnreadableCodeKeepsAccount(t *testing.T) {
	for _, reply := range []string{"", "53 x", "5xx x", "5350 x", "Incorrect authentication data"} {
		line := "dovecot_login authenticator failed for [203.0.113.7]: " + reply + " (set_id=a@example.com)"
		want := AuthFailureRecord{Authenticator: "dovecot_login", ClientIP: "203.0.113.7", Account: "a@example.com"}
		if got := AuthFailure(line); got != want {
			t.Fatalf("unreadable reply = %+v, want %+v", got, want)
		}
	}
}

func TestAuthFailureRejectsMarkersInOtherRecords(t *testing.T) {
	const fake = "dovecot_login authenticator failed for [192.0.2.9]:25: 535 Incorrect authentication data (set_id=b@example.com)"
	for _, line := range []string{
		"2026-04-14 12:00:00 SMTP syntax error in \"" + fake + "\" H=(client.example) [203.0.113.7]:54321",
		"2026-04-14 12:00:00 1abc-DEF-01 <= a@example.com H=(" + fake + ") [203.0.113.7]:54321 P=esmtp S=100",
		"2026-04-14 12:00:00 1abc-DEF-01 <= a@example.com H=(client.example) [203.0.113.7]:54321 P=esmtp S=100 T=\"" + fake + "\"",
	} {
		if got := AuthFailure(line); got != (AuthFailureRecord{}) {
			t.Fatalf("client text accepted as a failure: %+v", got)
		}
	}
}
