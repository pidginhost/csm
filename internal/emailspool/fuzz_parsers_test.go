package emailspool

import (
	"os"
	"strings"
	"testing"
)

// The Exim -H parser reads spool files whose header section is populated from
// attacker-controlled message headers (From, Subject, Reply-To, X-Mailer, and
// the envelope recipient list). A crafted spool file that panics the parser is
// a local DoS against the mail-scan path, so the parser must survive arbitrary
// input. This target also guards the variable-width length-prefix handling and
// the recipient-block anchoring against regressions.
//
// Run locally with:
//
//	go test -run=xxx -fuzz=FuzzParseHeadersReader -fuzztime=60s ./internal/emailspool/
func FuzzParseHeadersReader(f *testing.F) {
	// Real cPanel-Exim spool output as the primary seed.
	if data, err := os.ReadFile("testdata/sample_phpmailer.H"); err == nil {
		f.Add(string(data))
	}

	// Structurally valid minimal -H.
	f.Add("id-H\nuser 100 100\n<u@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n037  Subject: Hello\n")
	// 4-digit (variable-width) length prefix on an oversized header.
	f.Add("id-H\nuser 100 100\n<u@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n1010  Subject: " + strings.Repeat("x", 1000) + "\n")
	// Deleted-header flag ('*') and a folded continuation line.
	f.Add("id-H\nuser 100 100\n<u@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n020* X-Old: dropped\n048F From: Long Name\n\t<sender@example.com>\n")
	// Recipient-block anchoring edge cases.
	f.Add("id-H\nuser 100 100\n<u@example.com>\n0 0\n-local\n2\na@example.com\nb@example.org\n\n037  Subject: Two\n")
	f.Add("id-H\nuser 100 100\n<u@example.com>\n0 0\n-local\n9\nonly@example.com\n\n037  Subject: Mismatch\n")
	// Truncated / malformed / empty.
	f.Add("id-H\nuser 100 100\n")
	f.Add("only-one-line")
	f.Add("")
	f.Add("\n\n\n")

	f.Fuzz(func(t *testing.T, data string) {
		// Must not panic on any input; parse errors are returned, not fatal.
		_, _ = ParseHeadersReader(strings.NewReader(data))
	})
}

// The source key is read from the same attacker-influenced preamble. It must
// never panic and must stay a short, typed key.
func FuzzReadSource(f *testing.F) {
	if data, err := os.ReadFile("testdata/sample_phpmailer.H"); err == nil {
		f.Add(string(data))
	}
	f.Add("id-H\nuser 100 100\n<u@example.com>\n0 0\n-host_address 192.0.2.10.25\n-auth_id u@example.com\n1\nrcpt@example.com\n\n")
	f.Add("id-H\nuser 100 100\n<u@example.com>\n0 0\n--host_address 2001:db8::1.25\n-aclm _x 5\nab\ncd\n-local\n")
	f.Add("id-H\nuser 100 100\n<u@example.com>\n0 0\n-aclc 0 99999999\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, data string) {
		got, err := ReadSource(strings.NewReader(data))
		if err != nil {
			return
		}
		if got == "" || len(got) > 255 {
			t.Fatalf("source %q: want 1 to 255 bytes", got)
		}
		if !strings.HasPrefix(got, "auth:") && !strings.HasPrefix(got, "ip:") && !strings.HasPrefix(got, "uid:") {
			t.Fatalf("source %q: unknown prefix", got)
		}
	})
}
