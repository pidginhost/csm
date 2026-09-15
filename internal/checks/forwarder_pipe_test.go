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

func TestIsPipeForwarderEximCommandWords(t *testing.T) {
	const builtin = "/usr/local/cpanel/bin/autorespond"
	for _, tt := range []struct {
		name    string
		command string
		pipe    bool
	}{
		{"ascii whitespace", " \t\v\f" + builtin + "\tbob@example.com", false},
		{"single quoted", "'" + builtin + "' bob@example.com", false},
		{"double quoted", `"` + builtin + `" bob@example.com`, false},
		{"quoted escape", `"\x2fusr/local/cpanel/bin/autorespond" bob@example.com`, false},
		{"quoted octal escape", `"\57usr/local/cpanel/bin/autorespond" bob@example.com`, false},
		{"quoted literal escape", `"\/usr/local/cpanel/bin/autorespond" bob@example.com`, false},
		{"quoted word ends at quote", `"` + builtin + `"suffix`, false},
		{"nonbreaking space relative path", "\u00a0" + builtin, true},
		{"next line relative path", "\u0085" + builtin, true},
		{"unicode path suffix", builtin + "\u2003other", true},
		{"literal inner quotes", "/usr/local/cpanel/bin/auto'respond'", true},
		{"empty executable", `""` + builtin, true},
		{"literal bare backslash", `\` + builtin, true},
		{"escaped quote", `"` + builtin + `\"suffix"`, true},
		{"escaped backslash", `"` + builtin + `\\suffix"`, true},
		{"nul", builtin + "\x00suffix", true},
		{"escaped nul", `"` + builtin + `\0suffix"`, true},
		{"unterminated quote", `"` + builtin, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPipeForwarder("|" + tt.command); got != tt.pipe {
				t.Errorf("IsPipeForwarder(%q) = %v, want %v", tt.command, got, tt.pipe)
			}
		})
	}
}

func TestAuditValiasFilePreservesExecutableWhitespace(t *testing.T) {
	for _, ending := range []string{"\u00a0", "\u0085", "\u2003"} {
		t.Run(ending, func(t *testing.T) {
			dest := "|/usr/local/cpanel/bin/autorespond" + ending
			path := writeValiasFixture(t, "example.com", "bob@example.com: "+dest+"\n")
			got := auditValiasFile(path, "example.com", map[string]bool{"example.com": true}, &config.Config{})
			if len(got) != 1 || got[0].Check != "email_pipe_forwarder" ||
				got[0].Message != "Pipe forwarder detected: bob@example.com -> "+dest {
				t.Fatalf("findings = %+v, want the non-builtin executable reported intact", got)
			}
		})
	}
}

func TestParseValiasEntriesEscapedPipeQuotes(t *testing.T) {
	content := `bob@example.com: "|\"/usr/local/cpanel/bin/autorespond\" \"a,b\" bob@example.com", "|/home/bob/relay"` + "\n"
	entries, err := ParseValiasEntries(strings.NewReader(content), "example.com")
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %+v, err = %v; want two destinations", entries, err)
	}
	if want := `|"/usr/local/cpanel/bin/autorespond" "a,b" bob@example.com`; entries[0].Dest != want {
		t.Errorf("builtin destination = %q, want %q", entries[0].Dest, want)
	}
	if IsPipeForwarder(entries[0].Dest) || !IsPipeForwarder(entries[1].Dest) {
		t.Fatalf("wrong pipe classification: %+v", entries)
	}
	if entries[1].Dest != "|/home/bob/relay" {
		t.Errorf("second destination = %q", entries[1].Dest)
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
