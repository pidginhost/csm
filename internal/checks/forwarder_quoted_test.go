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
