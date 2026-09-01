package checks

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/signatures"
)

// WPCode executes PHP stored in the database. That makes the posts table an
// executable surface no file scanner covers: a full filesystem
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
			out = append(out, r[0]+"\t"+r[1]+"\t"+strconv.Itoa(len(r[2]))+"\t"+
				strings.ToUpper(hex.EncodeToString([]byte(r[2]))))
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
	if got[0].Severity != alert.Warning {
		t.Errorf("trashed stored code severity = %v, want Warning", got[0].Severity)
	}

	got = storedCodeFindings(t, [][3]string{{"2690", "draft", xorSnippet}})
	if len(got) != 1 || got[0].Severity != alert.High {
		t.Errorf("draft stored code = %+v, want one High finding", got)
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
		return []string{"", "1", "2\tpublish", "3\tpublish\t4\tZZZZ", "\t\t\t"}
	}
	t.Cleanup(func() { runMySQLQuery = prev })
	withRepoScanner(t)
	ctx, incomplete := withIncompleteCheckCollector(t.Context())
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p", queryCtx: ctx}
	if got := checkWPStoredCode("alice", creds, "wp_"); len(got) != 0 {
		t.Errorf("malformed rows produced findings: %d", len(got))
	}
	if !incomplete.contains("db_content") {
		t.Error("malformed stored-code rows did not mark the database scan incomplete")
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
		return []string{fmt.Sprintf("4052\tpublish\t%d\t%s", len(xorSnippet), truncated)}
	}
	t.Cleanup(func() { runMySQLQuery = prev })
	ctx, incomplete := withIncompleteCheckCollector(t.Context())
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p", queryCtx: ctx}
	if got := checkWPStoredCode("alice", creds, "wp_"); len(got) != 1 {
		t.Errorf("truncated hex: got %d findings, want 1 (decoded prefix must still be scanned)", len(got))
	}
	if !incomplete.contains("db_content") {
		t.Error("truncated hex did not mark the database scan incomplete")
	}
}

// Size-bounded rules use the complete stored value size, not the truncated
// prefix transferred to the scanner. Otherwise a large legitimate snippet can
// be judged by heuristics that are intentionally disabled for large content.
func TestStoredCode_UsesOriginalByteLengthForRuleBounds(t *testing.T) {
	withRepoScanner(t)
	const code = `$url = "\x68\x74\x74\x70\x3a\x2f\x2f\x65\x78\x61\x6d\x70\x6c\x65";`
	reportedSize := int64(len(code))
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if !strings.Contains(query, "post_type = 'wpcode'") {
			return nil
		}
		return []string{fmt.Sprintf("4052\tpublish\t%d\t%s", reportedSize,
			strings.ToUpper(hex.EncodeToString([]byte(code))))}
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	ctx, incomplete := withIncompleteCheckCollector(t.Context())
	creds := wpDBCreds{dbName: "wp", queryCtx: ctx}
	if got := checkWPStoredCode("alice", creds, "wp_"); len(got) == 0 {
		t.Fatal("complete small snippet did not exercise the size-bounded signature")
	}
	if incomplete.contains("db_content") {
		t.Fatal("complete stored snippet marked the database scan incomplete")
	}
	reportedSize = maxStoredCodeBytes + 1
	if got := checkWPStoredCode("alice", creds, "wp_"); len(got) != 0 {
		t.Errorf("large truncated snippet bypassed signature size bound: %+v", got)
	}
	if !incomplete.contains("db_content") {
		t.Error("byte-truncated stored snippet did not mark the database scan incomplete")
	}
}

func TestStoredCode_RowLimitMarksScanIncompleteAndPrioritizesActiveRows(t *testing.T) {
	prevScanner := contentSignatureScanner
	emptyScanner := signatures.NewScanner("")
	contentSignatureScanner = func() *signatures.Scanner { return emptyScanner }
	t.Cleanup(func() { contentSignatureScanner = prevScanner })

	prevQuery := runMySQLQuery
	var query string
	runMySQLQuery = func(_ wpDBCreds, q string) []string {
		query = q
		rows := make([]string, maxStoredCodeRows+1)
		for i := range rows {
			rows[i] = fmt.Sprintf("%d\tpublish\t1\t41", i+1)
		}
		return rows
	}
	t.Cleanup(func() { runMySQLQuery = prevQuery })

	ctx, incomplete := withIncompleteCheckCollector(t.Context())
	checkWPStoredCode("alice", wpDBCreds{dbName: "wp", queryCtx: ctx}, "wp_")
	if !incomplete.contains("db_content") {
		t.Fatal("stored-code row limit did not mark the database scan incomplete")
	}
	wantLimit := maxStoredCodeRows + 1
	if !strings.Contains(query, "LIMIT "+strconv.Itoa(wantLimit)) {
		t.Errorf("stored-code query limit = %q, want look-ahead limit %d", query, wantLimit)
	}
	if !strings.Contains(query, "OCTET_LENGTH(p.post_content)") ||
		!strings.Contains(query, "CAST(p.post_content AS BINARY)") {
		t.Errorf("stored-code query does not preserve byte-accurate size bounds: %s", query)
	}
	for _, clause := range []string{
		"JOIN wp_term_taxonomy",
		"JOIN wp_terms",
		"tt.taxonomy = 'wpcode_type'",
		"t.slug IN ('php', 'universal')",
	} {
		if !strings.Contains(query, clause) {
			t.Errorf("stored-code query does not restrict scanning to WPCode PHP snippets (%q missing): %s", clause, query)
		}
	}
	publishOrder := strings.Index(query, "WHEN 'publish' THEN 0")
	draftOrder := strings.Index(query, "WHEN 'draft' THEN 1")
	trashOrder := strings.Index(query, "WHEN 'trash' THEN 2")
	if publishOrder < 0 || draftOrder < publishOrder || trashOrder < draftOrder {
		t.Errorf("stored-code query does not prioritize active rows: %s", query)
	}
}

func TestStoredCode_ScansMultisiteSecondaryPosts(t *testing.T) {
	withRepoScanner(t)
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		switch {
		case strings.Contains(query, "FROM wp_blogs"):
			return []string{"2"}
		case strings.Contains(query, "FROM wp_2_posts") && strings.Contains(query, "post_type = 'wpcode'"):
			return []string{fmt.Sprintf("4052\tpublish\t%d\t%s", len(xorSnippet),
				strings.ToUpper(hex.EncodeToString([]byte(xorSnippet))))}
		default:
			return nil
		}
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	findings := scanMultisiteSecondaryBlogs(t.Context(), "alice", wpDBCreds{dbName: "network"}, "wp_")
	for _, finding := range findings {
		if finding.Check == "db_stored_code_execution" && strings.Contains(finding.Details, "Table prefix: wp_2_") {
			return
		}
	}
	t.Fatalf("secondary blog stored snippet was not reported: %+v", findings)
}
