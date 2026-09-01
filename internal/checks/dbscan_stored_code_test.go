package checks

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/signatures"
)

// Snippet-manager plugins execute PHP stored in the database. That makes the
// posts table an executable surface no file scanner covers: a full filesystem
// sweep of infiltratiizero.ro found nothing while a 17KB obfuscated backdoor
// ran on every request as WPCode snippet 4052.
func storedCodeRows(t *testing.T, rows [][3]string) {
	t.Helper()
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if !strings.Contains(query, "wpcode") {
			return nil
		}
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, r[0]+"\t"+r[1]+"\t"+strings.ToUpper(hex.EncodeToString([]byte(r[2]))))
		}
		return out
	}
	t.Cleanup(func() { runMySQLQuery = prev })
}

func withRepoScanner(t *testing.T) {
	t.Helper()
	prev := contentSignatureScanner
	sc := signatures.NewScanner("../../configs")
	contentSignatureScanner = func() *signatures.Scanner { return sc }
	t.Cleanup(func() { contentSignatureScanner = prev })
}

func storedCodeFindings(t *testing.T, rows [][3]string) []alert.Finding {
	t.Helper()
	withRepoScanner(t)
	storedCodeRows(t, rows)
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	var out []alert.Finding
	for _, f := range checkWPStoredCode("alice", creds, "wp_") {
		if f.Check == "db_stored_code_execution" {
			out = append(out, f)
		}
	}
	return out
}

// Live sample: the XOR-built identifiers of snippet 4052.
const xorSnippet = `if (defined("_WP_WEBSITE")) { return; }
if (!defined("\xf3\x69\x6d\xf9\x7b\x1a\x56\xbb" ^ "\xa4\x39\x32\xba\x3a\x59\x1e\xfe")) { return; }`

func TestStoredCode_ExecutingBackdoorIsCritical(t *testing.T) {
	got := storedCodeFindings(t, [][3]string{{"4052", "publish", xorSnippet}})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity != alert.Critical {
		t.Errorf("executing stored backdoor severity = %v, want Critical", got[0].Severity)
	}
}

// A trashed snippet cannot execute, but it is still evidence and must not be
// silently dropped -- 637 of them sat in that site's trash.
func TestStoredCode_NonExecutingIsLowerSeverity(t *testing.T) {
	got := storedCodeFindings(t, [][3]string{{"2689", "trash", xorSnippet}})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity == alert.Critical {
		t.Errorf("non-executing stored code severity = Critical, want lower")
	}
}

// Operators legitimately use snippet managers. Presence of a snippet, or of the
// plugin, is never a finding on its own -- only a payload marker is.
func TestStoredCode_BenignSnippetsStayQuiet(t *testing.T) {
	rows := [][3]string{
		{"2376", "publish", `add_action('wp_footer', function () { echo "<!-- thanks for reading -->"; });`},
		{"2377", "publish", `add_action('admin_init', function () { global $pagenow; if ($pagenow === 'edit-comments.php') { wp_redirect(admin_url()); exit; } });`},
		{"2675", "publish", ``},
	}
	if got := storedCodeFindings(t, rows); len(got) != 0 {
		t.Errorf("benign snippets produced findings: %d", len(got))
	}
}

// Malformed or truncated hex must not panic or invent findings.
func TestStoredCode_MalformedRows(t *testing.T) {
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if !strings.Contains(query, "wpcode") {
			return nil
		}
		return []string{"", "1", "2\tpublish", "3\tpublish\tZZZZ", "\t\t"}
	}
	t.Cleanup(func() { runMySQLQuery = prev })
	withRepoScanner(t)
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	if got := checkWPStoredCode("alice", creds, "wp_"); len(got) != 0 {
		t.Errorf("malformed rows produced findings: %d", len(got))
	}
}

// MySQL HEX() emits valid hex, so a decode error means truncated transport.
// The decoded prefix must still be scanned -- dropping it would report a
// backdoored site as clean.
func TestStoredCode_TruncatedHexStillScanned(t *testing.T) {
	withRepoScanner(t)
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if !strings.Contains(query, "wpcode") {
			return nil
		}
		truncated := strings.ToUpper(hex.EncodeToString([]byte(xorSnippet))) + "ZZ"
		return []string{"4052\tpublish\t" + truncated}
	}
	t.Cleanup(func() { runMySQLQuery = prev })
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	if got := checkWPStoredCode("alice", creds, "wp_"); len(got) != 1 {
		t.Errorf("truncated hex: got %d findings, want 1 (decoded prefix must still be scanned)", len(got))
	}
}
