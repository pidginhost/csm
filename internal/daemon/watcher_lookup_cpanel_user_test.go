package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// withUserdomainsPath points the package-level userdomainsPath at a
// caller-provided file for the duration of the test.
func withUserdomainsPath(t *testing.T, path string) {
	t.Helper()
	old := userdomainsPath
	userdomainsPath = path
	t.Cleanup(func() { userdomainsPath = old })
}

// writeUserdomains stages a /etc/userdomains fixture with the given body
// and returns its path.
func writeUserdomains(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "userdomains")
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLookupCPanelUserMissingFile(t *testing.T) {
	withUserdomainsPath(t, filepath.Join(t.TempDir(), "does-not-exist"))
	if got := lookupCPanelUser("example.com"); got != "" {
		t.Errorf("missing file should return empty string, got %q", got)
	}
}

func TestLookupCPanelUserExactMatch(t *testing.T) {
	body := "example.com: alice\n" +
		"other.com: bob\n"
	withUserdomainsPath(t, writeUserdomains(t, body))

	if got := lookupCPanelUser("example.com"); got != "alice" {
		t.Errorf("lookup('example.com') = %q, want %q", got, "alice")
	}
	if got := lookupCPanelUser("other.com"); got != "bob" {
		t.Errorf("lookup('other.com') = %q, want %q", got, "bob")
	}
}

func TestLookupCPanelUserCaseInsensitive(t *testing.T) {
	// cPanel writes lowercase. If an incoming query has mixed case, the
	// strings.EqualFold comparison means we still find the owner.
	withUserdomainsPath(t, writeUserdomains(t, "example.com: alice\n"))
	if got := lookupCPanelUser("Example.COM"); got != "alice" {
		t.Errorf("case-insensitive match failed, got %q", got)
	}
}

func TestLookupCPanelUserUnknownDomain(t *testing.T) {
	withUserdomainsPath(t, writeUserdomains(t, "example.com: alice\n"))
	if got := lookupCPanelUser("not-listed.com"); got != "" {
		t.Errorf("unknown domain should return empty, got %q", got)
	}
}

func TestLookupCPanelUserSkipsMalformedLines(t *testing.T) {
	body := "# comment line without colon\n" +
		"malformed no separator\n" +
		"example.com: alice\n" +
		"\n" + // blank
		"also-malformed\n"
	withUserdomainsPath(t, writeUserdomains(t, body))
	if got := lookupCPanelUser("example.com"); got != "alice" {
		t.Errorf("valid entry among malformed lines should still match, got %q", got)
	}
}

func TestLookupCPanelUserTrimsWhitespace(t *testing.T) {
	// cPanel aligns usernames with variable whitespace — the parser must
	// strip it from both domain and username.
	body := "   example.com  :   alice   \n"
	withUserdomainsPath(t, writeUserdomains(t, body))
	if got := lookupCPanelUser("example.com"); got != "alice" {
		t.Errorf("expected whitespace-trimmed match, got %q", got)
	}
}
