package emailspool

import (
	"strings"
	"testing"
)

// buildSpoolH assembles an Exim -H file body: a fixed envelope preamble, an
// optional recipient block (count line + addresses), the blank separator, and
// one header line. recipientLines is inserted verbatim so malformed blocks can
// be exercised; countLine is the bare recipient count.
func buildSpoolH(countLine string, recipientLines []string) string {
	var b strings.Builder
	b.WriteString("1abcDE-0000000G8Fo-1FA1-H\n")
	b.WriteString("exampleuser 1168 982\n")
	b.WriteString("<exampleuser@cpanel.example.test>\n")
	b.WriteString("1777409086 0\n")
	b.WriteString("-received_time_usec .296607\n")
	b.WriteString("-body_linecount 21\n")
	b.WriteString("-local\n")
	if countLine != "" {
		b.WriteString(countLine + "\n")
	}
	for _, r := range recipientLines {
		b.WriteString(r + "\n")
	}
	b.WriteString("\n") // envelope/header separator
	b.WriteString("037  Subject: Hello\n")
	return b.String()
}

func TestParseHeaders_ExtractsEnvelopeRecipients(t *testing.T) {
	in := buildSpoolH("2", []string{"admin@example.com", "ops@example.org"})
	h, err := ParseHeadersReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Recipients) != 2 {
		t.Fatalf("Recipients = %v, want 2", h.Recipients)
	}
	if h.Recipients[0] != "admin@example.com" || h.Recipients[1] != "ops@example.org" {
		t.Fatalf("Recipients = %v, want [admin@example.com ops@example.org]", h.Recipients)
	}
}

func TestParseHeaders_SingleRecipient(t *testing.T) {
	in := buildSpoolH("1", []string{"info@example.com"})
	h, err := ParseHeadersReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Recipients) != 1 || h.Recipients[0] != "info@example.com" {
		t.Fatalf("Recipients = %v, want [info@example.com]", h.Recipients)
	}
}

// A recipient line with trailing Exim fields keeps only the address token.
func TestParseHeaders_RecipientWithTrailingFields(t *testing.T) {
	in := buildSpoolH("1", []string{"victim@example.net <> 0,1"})
	h, err := ParseHeadersReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Recipients) != 1 || h.Recipients[0] != "victim@example.net" {
		t.Fatalf("Recipients = %v, want [victim@example.net]", h.Recipients)
	}
}

// Count says 3 but only one address precedes the blank line: the anchor does
// not validate, so recipients are reported unknown (empty) rather than guessed.
func TestParseHeaders_CountMismatchYieldsUnknown(t *testing.T) {
	in := buildSpoolH("3", []string{"only@example.com"})
	h, err := ParseHeadersReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Recipients) != 0 {
		t.Fatalf("Recipients = %v, want empty on count mismatch", h.Recipients)
	}
}

// No recipient block at all: recipients unknown, parse still succeeds.
func TestParseHeaders_NoRecipientBlock(t *testing.T) {
	in := buildSpoolH("", nil)
	h, err := ParseHeadersReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Recipients) != 0 {
		t.Fatalf("Recipients = %v, want empty", h.Recipients)
	}
}

// A bare integer appearing in option data must not be mistaken for the
// recipient count when its claimed run does not reach the end of the preamble.
func TestParseHeaders_DecoyIntegerNotTreatedAsCount(t *testing.T) {
	in := buildSpoolH("1", []string{"real@example.com"})
	// Inject a decoy "5" option value line above the real block.
	in = strings.Replace(in, "-local\n", "-local\n5\n", 1)
	h, err := ParseHeadersReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	// The decoy "5" cannot anchor (5 lines don't reach preamble end); the real
	// "1" + one address does. A "5" with a non-address tail also fails the
	// per-recipient '@' check.
	if len(h.Recipients) != 1 || h.Recipients[0] != "real@example.com" {
		t.Fatalf("Recipients = %v, want [real@example.com]", h.Recipients)
	}
}

// ACL/option data above the recipient block may contain bare integers and
// email-like payloads. It must not be treated as the recipient count; ambiguity
// should fail open instead of returning a partial recipient suffix.
func TestParseHeaders_ACLDataAnchoredDecoyYieldsUnknown(t *testing.T) {
	in := buildSpoolH("2", []string{"real1@example.com", "real2@example.com"})
	in = strings.Replace(in, "-local\n", "-local\n4\nacl@example.com\n", 1)
	h, err := ParseHeadersReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Recipients) != 0 {
		t.Fatalf("Recipients = %v, want empty on anchored ACL decoy", h.Recipients)
	}
}

// If the claimed recipient block itself fails the '@' shape check, do not
// salvage a later suffix that happens to start with a bare integer. Returning a
// subset could make recipient diversity look low and suppress a real relay.
func TestParseHeaders_MalformedRecipientBlockDoesNotReturnSuffix(t *testing.T) {
	in := buildSpoolH("3", []string{"victim1@example.com", "1", "victim2@example.net"})
	h, err := ParseHeadersReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Recipients) != 0 {
		t.Fatalf("Recipients = %v, want empty on malformed recipient block", h.Recipients)
	}
}
