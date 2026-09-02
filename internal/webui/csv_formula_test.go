package webui

import (
	"strings"
	"testing"
)

// A finding message beginning with "=", "+", "-" or "@" (attacker-chosen
// text: a filename, a User-Agent, a mailbox) turned into a live formula when
// the exported CSV was opened in a spreadsheet. Such fields are prefixed so
// they render as text.
func TestCSVEscapeNeutralisesFormulaPrefixes(t *testing.T) {
	for _, in := range []string{"=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\t=1+1", "\r=1"} {
		out := csvEscape(in)
		body := strings.Trim(out, "\"")
		if strings.HasPrefix(body, "=") || strings.HasPrefix(body, "+") || strings.HasPrefix(body, "-") || strings.HasPrefix(body, "@") || strings.HasPrefix(body, "\t") || strings.HasPrefix(body, "\r") {
			t.Fatalf("%q exported as %q, still starts with a formula trigger", in, out)
		}
		if !strings.Contains(out, strings.TrimLeft(in, "\t\r")) {
			t.Fatalf("%q exported as %q, original text lost", in, out)
		}
	}
	if got := csvEscape("plain text"); got != "plain text" {
		t.Fatalf("plain text altered: %q", got)
	}
	if got := csvEscape("a,b"); got != "\"a,b\"" {
		t.Fatalf("comma quoting changed: %q", got)
	}
}
