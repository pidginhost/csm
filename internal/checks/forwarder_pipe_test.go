package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// cPanel writes Mailman list aliases as pipes to its own Mailman binaries
// under 3rdparty. They run only cPanel's list software, so they are not
// attacker-controlled command execution.
func TestIsPipeForwarderIgnoresCPanelMailmanAliases(t *testing.T) {
	for _, dest := range []string{
		"|/usr/local/cpanel/3rdparty/mailman/mail/mailman post list_example.com",
		"|/usr/local/cpanel/3rdparty/mailman/mail/mailman admin list_example.com",
		"|/usr/local/cpanel/3rdparty/mailman/mail/wrapper mailowner list_example.com",
		"|/usr/local/cpanel/3rdparty/mailman/mail/wrapper post list_example.com",
	} {
		if IsPipeForwarder(dest) {
			t.Errorf("IsPipeForwarder(%q) = true, want false for cPanel Mailman alias", dest)
		}
	}
}

// A builtin binary path appearing anywhere but as the executed command must
// not hide the pipe.
func TestIsPipeForwarderFlagsBuiltinPathNotExecuted(t *testing.T) {
	for _, dest := range []string{
		"|/home/bob/.x/relay.sh /usr/local/cpanel/bin/autorespond",
		"|/home/bob/usr/local/cpanel/bin/boxtrapper",
		"|/usr/bin/php /home/bob/x.php --tag=/usr/local/cpanel/3rdparty/mailman/mail/mailman",
		"|/usr/local/cpanel/3rdparty/mailman/mail/mailman.sh post list_example.com",
	} {
		if !IsPipeForwarder(dest) {
			t.Errorf("IsPipeForwarder(%q) = false, want true", dest)
		}
	}
}

func writeValiasFixture(t *testing.T, domain, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), domain)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func pipeFindings(findings []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == "email_pipe_forwarder" {
			out = append(out, f)
		}
	}
	return out
}

// cPanel valiases keys carry the full address. The mailbox must be named
// once, not with the file domain appended a second time.
func TestAuditValiasFileNamesFullAddressMailboxOnce(t *testing.T) {
	path := writeValiasFixture(t, "example.com", `bob@example.com: "|/home/bob/.x/relay.sh"`+"\n")

	got := pipeFindings(auditValiasFile(path, "example.com", map[string]bool{"example.com": true}, &config.Config{}))
	if len(got) != 1 {
		t.Fatalf("pipe findings = %+v, want exactly 1", got)
	}
	if want := "Pipe forwarder detected: bob@example.com -> |/home/bob/.x/relay.sh"; got[0].Message != want {
		t.Errorf("message = %q, want %q", got[0].Message, want)
	}
	if !strings.Contains(got[0].Details, "Local part: bob\n") {
		t.Errorf("details = %q, want local part without domain", got[0].Details)
	}
}

// The documented known_forwarders form "local@domain: dest" must match a
// valiases line keyed by the full address.
func TestAuditValiasFileKnownForwarderMatchesFullAddressKey(t *testing.T) {
	path := writeValiasFixture(t, "example.com", `bob@example.com: "|/home/bob/.x/relay.sh"`+"\n")
	cfg := &config.Config{}
	cfg.EmailProtection.KnownForwarders = []string{"bob@example.com: |/home/bob/.x/relay.sh"}

	if got := auditValiasFile(path, "example.com", map[string]bool{"example.com": true}, cfg); len(got) != 0 {
		t.Fatalf("findings = %+v, want known forwarder suppressed", got)
	}
}

func TestParseValiasEntriesSplitsAddressAndUnquotes(t *testing.T) {
	content := strings.Join([]string{
		`# comment`,
		`bob@example.com: "|/home/bob/.x/relay.sh --to a,b", carol@example.net`,
		`plain: dave@example.com`,
		`erin@example.com: "|/home/erin/r.sh --to a,b"`,
		`*: :fail: No Such User Here`,
		``,
	}, "\n")

	got, err := ParseValiasEntries(strings.NewReader(content), "example.com")
	want := []ValiasEntry{
		{LocalPart: "bob", Domain: "example.com", Dest: "|/home/bob/.x/relay.sh --to a,b"},
		{LocalPart: "bob", Domain: "example.com", Dest: "carol@example.net"},
		{LocalPart: "plain", Domain: "example.com", Dest: "dave@example.com"},
		{LocalPart: "erin", Domain: "example.com", Dest: "|/home/erin/r.sh --to a,b"},
		{LocalPart: "*", Domain: "example.com", Dest: ":fail: No Such User Here"},
	}
	if len(got) != len(want) {
		t.Fatalf("entries = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

// A cPanel built-in pipe carries the mailbox address as an argument. It is
// a command, not a forwarding address, even in a file changed since baseline.
func TestAuditValiasFileBuiltinPipeIsNotExternalForwarder(t *testing.T) {
	db := withTestStore(t)
	if err := db.SetMetaString("email:fwd_last_refresh", "2026-06-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	path := writeValiasFixture(t, "example.com",
		`bob@example.com: "|/usr/local/cpanel/bin/autorespond bob@example.com /home/bob/.autorespond"`+"\n")

	if got := auditValiasFile(path, "example.com", map[string]bool{"example.com": true}, &config.Config{}); len(got) != 0 {
		t.Fatalf("findings = %+v, want none for cPanel autoresponder", got)
	}
}
