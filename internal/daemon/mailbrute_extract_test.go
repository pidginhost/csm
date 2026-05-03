package daemon

import "testing"

func TestExtractAccountKey_BuiltinDovecotUser(t *testing.T) {
	ex, err := NewAccountExtractor("builtin:dovecot-user")
	if err != nil {
		t.Fatal(err)
	}
	got := ex.Extract("Jan  2 12:00:00 host dovecot: imap-login: Aborted: user=<alice@example.com>, ...")
	if got != "alice@example.com" {
		t.Fatalf("expected alice@example.com, got %q", got)
	}
}

func TestExtractAccountKey_BuiltinPostfixSasl(t *testing.T) {
	ex, err := NewAccountExtractor("builtin:postfix-sasl")
	if err != nil {
		t.Fatal(err)
	}
	got := ex.Extract("postfix/smtpd: warning: ... sasl_method=PLAIN, sasl_username=alice@example.com")
	if got != "alice@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractAccountKey_RegexCustom(t *testing.T) {
	ex, err := NewAccountExtractor(`regex:phpanel-mailbox=([^\s,]+)`)
	if err != nil {
		t.Fatal(err)
	}
	got := ex.Extract("phpanel-mailbox=tenant1!alice")
	if got != "tenant1!alice" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractAccountKey_RegexRequiresCaptureGroup(t *testing.T) {
	_, err := NewAccountExtractor(`regex:phpanel-mailbox=[^\s,]+`)
	if err == nil {
		t.Fatal("expected error for regex without capture group")
	}
}

func TestExtractAccountKey_NoMatchReturnsEmpty(t *testing.T) {
	ex, _ := NewAccountExtractor("builtin:dovecot-user")
	if got := ex.Extract("nothing useful here"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestExtractAccountKey_EmptySpecDefaultsToDovecotUser(t *testing.T) {
	ex, err := NewAccountExtractor("")
	if err != nil {
		t.Fatal(err)
	}
	got := ex.Extract("user=<bob@example.com>")
	if got != "bob@example.com" {
		t.Fatalf("expected bob@example.com, got %q", got)
	}
}
