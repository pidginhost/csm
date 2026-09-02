package checks

import "testing"

// cPanel writes pipe destinations quoted ("|/path args"), and the pipe
// detector only looked for a bare leading "|", so every quoted pipe
// forwarder was invisible.
func TestParseValiasLineUnquotesPipeDestination(t *testing.T) {
	_, dest := parseValiasLine(`bob@example.com: "|/home/bob/.x/relay.sh --to attacker"`)
	if dest != "|/home/bob/.x/relay.sh --to attacker" {
		t.Fatalf("dest = %q, want the unquoted pipe", dest)
	}
	if !isPipeForwarder(dest) {
		t.Fatal("quoted pipe destination not detected as a pipe forwarder")
	}
}

func TestParseValiasLineUnquotesSingleQuotedDestination(t *testing.T) {
	_, dest := parseValiasLine(`bob@example.com: '|/usr/bin/php /home/bob/mailer.php'`)
	if dest != "|/usr/bin/php /home/bob/mailer.php" {
		t.Fatalf("dest = %q", dest)
	}
}

func TestParseValiasLineKeepsSafeQuotedBuiltins(t *testing.T) {
	_, dest := parseValiasLine(`bob@example.com: "|/usr/local/cpanel/bin/autorespond bob@example.com /home/bob/.autorespond"`)
	if isPipeForwarder(dest) {
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
	if len(dests) != 2 || !isPipeForwarder(dests[0]) {
		t.Fatalf("unterminated quote hid pipe destination: %#v", dests)
	}
}
