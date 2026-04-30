package emailspool

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestExtractDomain_BareAddress(t *testing.T) {
	got := ExtractDomain("user@Example.COM")
	if got != "example.com" {
		t.Fatalf("want example.com, got %q", got)
	}
}

func TestExtractDomain_DisplayName(t *testing.T) {
	got := ExtractDomain(`"Display Name" <user@example.com>`)
	if got != "example.com" {
		t.Fatalf("want example.com, got %q", got)
	}
}

func TestExtractDomain_QuotedLocalPart(t *testing.T) {
	got := ExtractDomain(`"a@b"@example.com`)
	if got != "example.com" {
		t.Fatalf("want example.com, got %q", got)
	}
}

func TestExtractDomain_Empty(t *testing.T) {
	if ExtractDomain("") != "" {
		t.Fatal("empty input must return empty domain")
	}
}

func TestExtractDomain_NoAtSign(t *testing.T) {
	// Input with no '@' anywhere (raw token) must return empty rather than
	// the input itself. Previously protected by the local extractDomain
	// shadow tests (TestExtractDomainNoAt, TestExtractDomainFormats).
	if got := ExtractDomain("nodomain"); got != "" {
		t.Errorf("ExtractDomain(\"nodomain\") = %q, want empty", got)
	}
	if got := ExtractDomain("no-at-sign"); got != "" {
		t.Errorf("ExtractDomain(\"no-at-sign\") = %q, want empty", got)
	}
}

func TestExtractDomain_Subdomain(t *testing.T) {
	// Multi-label domain on the right side of '@' must be preserved verbatim
	// (lowercased). Previously protected by TestExtractDomainWithSubdomain.
	if got := ExtractDomain("user@sub.example.com"); got != "sub.example.com" {
		t.Errorf("ExtractDomain subdomain = %q", got)
	}
}

func TestExtractDomain_EmptyAngleBrackets(t *testing.T) {
	// Bounce-style "<>" envelope marker has no address; must return empty.
	// Previously protected by TestExtractDomainBounce.
	if got := ExtractDomain("<>"); got != "" {
		t.Errorf("ExtractDomain(\"<>\") = %q, want empty", got)
	}
}

func TestIsSubdomainOrEqual(t *testing.T) {
	cases := []struct {
		candidate, base string
		want            bool
	}{
		{"foo.com", "foo.com", true},
		{"FOO.com", "foo.com", true},
		{"mail.foo.com", "foo.com", true},
		{"deep.mail.foo.com", "foo.com", true},
		{"foo.com", "mail.foo.com", false},
		{"barfoo.com", "foo.com", false},
		{"", "foo.com", false},
		{"foo.com", "", false},
	}
	for _, c := range cases {
		if got := IsSubdomainOrEqual(c.candidate, c.base); got != c.want {
			t.Errorf("IsSubdomainOrEqual(%q,%q)=%v, want %v", c.candidate, c.base, got, c.want)
		}
	}
}

func TestParseHeaders_PHPMailerFixture(t *testing.T) {
	h, err := ParseHeaders("testdata/sample_phpmailer.H")
	if err != nil {
		t.Fatalf("ParseHeaders error: %v", err)
	}
	if h.EnvelopeUser != "exampleuser" {
		t.Errorf("EnvelopeUser = %q, want exampleuser", h.EnvelopeUser)
	}
	if h.EnvelopeUID != 1168 {
		t.Errorf("EnvelopeUID = %d, want 1168", h.EnvelopeUID)
	}
	if h.From != "Spoof <attacker@spoofed.example>" {
		t.Errorf("From = %q", h.From)
	}
	if h.ReplyTo != "attacker@gmail.example" {
		t.Errorf("ReplyTo = %q", h.ReplyTo)
	}
	if h.XPHPScript != "rentvsloan.example.com/wp-admin/admin-ajax.php for 192.0.2.10" {
		t.Errorf("XPHPScript = %q", h.XPHPScript)
	}
	if h.XMailer != "PHPMailer 7.0.0 (https://github.com/PHPMailer/PHPMailer)" {
		t.Errorf("XMailer = %q", h.XMailer)
	}
	// Subject is also extracted via the same NNNX-prefixed parse path; assert
	// it explicitly so the contract previously protected by the deleted
	// extractEmailHeader shadow tests stays covered here.
	if h.Subject != "Hello" {
		t.Errorf("Subject = %q, want Hello", h.Subject)
	}
}

func TestParseHeaders_NoXPHPScript(t *testing.T) {
	// Confirm a spool file without X-PHP-Script returns Headers{} with empty XPHPScript.
	// Use a tmp file so we don't need a separate fixture.
	dir := t.TempDir()
	path := dir + "/no-xphp.H"
	content := "id1-H\nuser 100 100\n<user@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n037T To: rcpt@example.com\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := ParseHeaders(path)
	if err != nil {
		t.Fatalf("ParseHeaders error: %v", err)
	}
	if h.XPHPScript != "" {
		t.Errorf("XPHPScript = %q, want empty", h.XPHPScript)
	}
	if h.EnvelopeUser != "user" {
		t.Errorf("EnvelopeUser = %q", h.EnvelopeUser)
	}
}

func TestParseHeaders_CapturesUserAgent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ua.H"
	content := "id-H\nuser 100 100\n<user@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n037T To: rcpt@example.com\n025  User-Agent: MailTool/1.0\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := ParseHeaders(path)
	if err != nil {
		t.Fatalf("ParseHeaders error: %v", err)
	}
	if h.UserAgent != "MailTool/1.0" {
		t.Errorf("UserAgent = %q, want MailTool/1.0", h.UserAgent)
	}
}

func TestParseHeaders_TooLargeReturnsErrTooLong(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/huge.H"
	var sb strings.Builder
	sb.WriteString("id-H\nuser 1 1\n<u@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n")
	// One header line longer than MaxSpoolHeaderBytes triggers ErrTooLong.
	sb.WriteString("999X X-Big: ")
	for i := 0; i < MaxSpoolHeaderBytes+1024; i++ {
		sb.WriteByte('a')
	}
	sb.WriteByte('\n')
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ParseHeaders(path)
	if err == nil {
		t.Fatal("expected error on oversize header")
	}
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("err = %v, want errors.Is(..., bufio.ErrTooLong)", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %q, want path in message", err.Error())
	}
}

func TestParseHeaders_TruncatedNoSeparatorReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/truncated.H"
	// Has line 1, line 2, some envelope metadata, but no blank line separator.
	content := "id-H\nuser 1 1\n<u@example.com>\n0 0\n-local\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ParseHeaders(path)
	if err == nil {
		t.Fatal("expected error on truncated file")
	}
	if !strings.Contains(err.Error(), "missing header section separator") {
		t.Errorf("err = %q, want path/missing header section separator wording", err.Error())
	}
}
