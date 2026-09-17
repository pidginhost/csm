package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Strict structured-path cases keep Message and Details empty so only the
// FilePath branch can attribute; the legacy text fallback has its own tests.
func TestExtractAccountStructuredPathIsLexicalAndBounded(t *testing.T) {
	withAccountHomeRoots(t, "/home", "/var/www/vhosts")
	cases := map[string]string{
		"/home/alice/public_html/x.php":      "alice",
		"/var/www/vhosts/bob/httpdocs/y.php": "bob",
		"/home/alice":                        "",
		"/home/alice/":                       "",
		"/home":                              "",
		"/home/":                             "",
		"/homes/alice/x.php":                 "",
		"/home2/alice/x.php":                 "",
		"home/alice/x.php":                   "",
		"/home/alice/../bob/x.php":           "bob",
		"/home/alice/./x.php":                "alice",
		"/home/../etc/passwd":                "",
		"/home/Alice/x.php":                  "Alice",
		"":                                   "",
	}
	for path, want := range cases {
		if got := extractAccountFromFinding(alert.Finding{FilePath: path}); got != want {
			t.Errorf("FilePath %q attributed to %q, want %q", path, got, want)
		}
	}
}

func TestExtractAccountPrecedence(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	cases := []struct {
		name string
		f    alert.Finding
		want string
	}{
		{"tenant wins over path and text", alert.Finding{TenantID: "alice", FilePath: "/home/bob/x.php", Message: "/home/carol/y.php"}, "alice"},
		{"tenant is verbatim and case-sensitive", alert.Finding{TenantID: "Alice", FilePath: "/home/alice/x.php"}, "Alice"},
		{"tenant unknown sentinel is still verbatim", alert.Finding{TenantID: "unknown", FilePath: "/home/alice/x.php"}, "unknown"},
		{"path wins over text", alert.Finding{FilePath: "/home/bob/x.php", Details: "see /home/carol/y.php"}, "bob"},
		{"relative path falls through to text", alert.Finding{FilePath: "home/bob/x.php", Message: "in /home/carol/z.php"}, "carol"},
		{"message before details", alert.Finding{Message: "in /home/carol/a", Details: "also /home/bob/b"}, "carol"},
		{"details fallback", alert.Finding{Details: "Account: /home/bob/etc"}, "bob"},
		{"account label text is not recognised", alert.Finding{Message: "rogue admin (account: bob)"}, ""},
		{"nothing", alert.Finding{}, ""},
	}
	for _, tc := range cases {
		if got := extractAccountFromFinding(tc.f); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

// The legacy text fallback searches configured roots in order within each
// field and matches an embedded root substring; these are recorded limits,
// not a contract for new producers.
func TestExtractAccountLegacyTextFallbackLimits(t *testing.T) {
	withAccountHomeRoots(t, "/srv/vhosts", "/home")
	f := alert.Finding{Message: "copied /home/bob/a.php to /srv/vhosts/alice/b.php"}
	if got := extractAccountFromFinding(f); got != "alice" {
		t.Errorf("root-order search: got %q, want alice (first configured root wins, not leftmost text)", got)
	}
	embedded := alert.Finding{Message: "backup at /opt/backups/home/carol/site.tgz"}
	if got := extractAccountFromFinding(embedded); got != "carol" {
		t.Errorf("embedded root substring: got %q, want carol", got)
	}
}
