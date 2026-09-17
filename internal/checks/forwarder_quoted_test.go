package checks

import (
	"strings"
	"testing"
)

func parseSingleValiasDest(t *testing.T, line string) string {
	t.Helper()
	entries, err := ParseValiasEntries(strings.NewReader(line+"\n"), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %+v, want one", entries)
	}
	return entries[0].Dest
}

// cPanel writes pipe destinations quoted ("|/path args"), and the pipe
// detector only looked for a bare leading "|", so every quoted pipe
// forwarder was invisible.
func TestParseValiasLineUnquotesPipeDestination(t *testing.T) {
	dest := parseSingleValiasDest(t, `bob@example.com: "|/home/bob/.x/relay.sh --to attacker"`)
	if dest != "|/home/bob/.x/relay.sh --to attacker" {
		t.Fatalf("dest = %q, want the unquoted pipe", dest)
	}
	if !IsPipeForwarder(dest) {
		t.Fatal("quoted pipe destination not detected as a pipe forwarder")
	}
}

func TestParseValiasLineUnquotesSingleQuotedDestination(t *testing.T) {
	dest := parseSingleValiasDest(t, `bob@example.com: '|/usr/bin/php /home/bob/mailer.php'`)
	if dest != "|/usr/bin/php /home/bob/mailer.php" {
		t.Fatalf("dest = %q", dest)
	}
}

func TestParseValiasLineKeepsSafeQuotedBuiltins(t *testing.T) {
	dest := parseSingleValiasDest(t, `bob@example.com: "|/usr/local/cpanel/bin/autorespond bob@example.com /home/bob/.autorespond"`)
	if IsPipeForwarder(dest) {
		t.Fatalf("cPanel autoresponder flagged as pipe forwarder: %q", dest)
	}
}

func TestSplitValiasDestsDoesNotHideAfterUnterminatedQuote(t *testing.T) {
	dests := splitValiasDests(`"local@example.com, attacker@external.test`)
	if len(dests) != 2 {
		t.Fatalf("dests = %#v, want two conservatively split destinations", dests)
	}
	if dests[1] != "attacker@external.test" {
		t.Fatalf("second destination = %q, want attacker address", dests[1])
	}
}

func TestSplitValiasDestsExposesPipeAfterUnterminatedQuote(t *testing.T) {
	dests := splitValiasDests(`"|/home/bob/dropper, local@example.com`)
	if len(dests) != 2 || !IsPipeForwarder(dests[0]) {
		t.Fatalf("unterminated quote hid pipe destination: %#v", dests)
	}
}
