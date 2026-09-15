package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestParseValiasFileForFindings(t *testing.T) {
	// Create a temporary valiases file
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com")
	content := `info: admin@gmail.com
support: user@example.com
deploy: |/usr/bin/deploy.sh
blackhole: /dev/null
*: catchall@external.io
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	localDomains := map[string]bool{
		"example.com": true,
	}
	knownForwarders := []string{}

	findings := parseValiasFileForFindings(path, "example.com", localDomains, knownForwarders)

	// Should detect:
	// 1. info -> admin@gmail.com (external)
	// 2. deploy -> |/usr/bin/deploy.sh (pipe) - CRITICAL
	// 3. blackhole -> /dev/null
	// 4. * -> catchall@external.io (wildcard external)
	// Should NOT detect:
	// support -> user@example.com (local)

	if len(findings) != 4 {
		t.Errorf("expected 4 findings, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  %s: %s", f.Check, f.Message)
		}
	}

	// Verify pipe forwarder is CRITICAL
	hasCriticalPipe := false
	for _, f := range findings {
		if f.Check == "email_pipe_forwarder" {
			hasCriticalPipe = true
		}
	}
	if !hasCriticalPipe {
		t.Error("expected a CRITICAL pipe forwarder finding")
	}
}

func TestParseValiasFileForFindings_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com")
	if err := os.WriteFile(path, []byte("# only comments\n\n"), 0644); err != nil {
		t.Fatal(err)
	}

	localDomains := map[string]bool{"example.com": true}
	findings := parseValiasFileForFindings(path, "example.com", localDomains, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestParseValiasFileForFindings_Suppressed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com")
	content := `info: admin@gmail.com
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	localDomains := map[string]bool{"example.com": true}
	knownForwarders := []string{"info@example.com: admin@gmail.com"}

	findings := parseValiasFileForFindings(path, "example.com", localDomains, knownForwarders)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (suppressed), got %d", len(findings))
	}
}

// cPanel quotes pipe destinations. The realtime parser must see through the
// quotes or every cPanel-written pipe forwarder is invisible to it.
func TestParseValiasFileForFindings_QuotedPipeDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "example.com")
	content := `bob@example.com: "|/home/bob/.x/relay.sh --to attacker"` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := parseValiasFileForFindings(path, "example.com", map[string]bool{"example.com": true}, nil)
	if len(findings) != 1 || findings[0].Check != "email_pipe_forwarder" {
		t.Fatalf("findings = %+v, want one email_pipe_forwarder", findings)
	}
	if want := "Pipe forwarder detected: bob@example.com -> |/home/bob/.x/relay.sh --to attacker"; findings[0].Message != want {
		t.Errorf("message = %q, want %q", findings[0].Message, want)
	}
}

func TestParseValiasFileForFindings_CPanelBuiltinPipesIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "example.com")
	content := `bob@example.com: "|/usr/local/cpanel/bin/autorespond bob@example.com /home/bob/.autorespond"
list@example.com: "|/usr/local/cpanel/3rdparty/mailman/mail/mailman post list_example.com"
list-admin@example.com: "|/usr/local/cpanel/3rdparty/mailman/mail/wrapper mailowner list_example.com"
box@example.com: "|/usr/local/cpanel/bin/boxtrapper box@example.com"
quoted@example.com: "|\"/usr/local/cpanel/bin/autorespond\" \"name, bob@example.com\" /home/bob/.autorespond"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if findings := parseValiasFileForFindings(path, "example.com", map[string]bool{"example.com": true}, nil); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for cPanel builtin pipes", findings)
	}
}

func TestParseValiasFileForFindings_FirstSightKeepsDangerousDestinations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "example.com")
	content := "bob@example.com: \"|\u00a0/usr/local/cpanel/bin/autorespond\", \"/dev/null\", external@example.net\n" +
		"box@example.com: \"|/usr/local/cpanel/bin/boxtrapper box@example.com\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, includeExternal := range []bool{false, true} {
		got := parseValiasFileForFindingsFiltered(path, "example.com", map[string]bool{"example.com": true}, nil, includeExternal)
		wantCount := 2
		if includeExternal {
			wantCount++
		}
		if len(got) != wantCount {
			t.Fatalf("includeExternal=%t: findings = %+v, want %d", includeExternal, got, wantCount)
		}
		if got[0].Check != "email_pipe_forwarder" || got[0].Severity != alert.Critical ||
			got[1].Message != "Mail blackhole: bob@example.com -> /dev/null" || got[1].Severity != alert.High {
			t.Fatalf("includeExternal=%t: wrong dangerous findings: %+v", includeExternal, got)
		}
		if includeExternal && got[2].Message != "External forwarder: bob@example.com -> external@example.net" {
			t.Errorf("external finding = %+v", got[2])
		}
	}
}

func TestParseValiasFileForFindings_KnownForwarderFullAddressKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "example.com")
	if err := os.WriteFile(path, []byte("bob@example.com: carol@example.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	known := []string{"bob@example.com: carol@example.net"}
	if findings := parseValiasFileForFindings(path, "example.com", map[string]bool{"example.com": true}, known); len(findings) != 0 {
		t.Fatalf("findings = %+v, want known forwarder suppressed", findings)
	}
}
