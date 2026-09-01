package checks

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Deleting spam posts does not remove the categories and tags they were filed
// under, and those archives are public pages. On infiltratiizero.ro the
// homepage still rendered gambling links after every spam post was gone,
// because 22 attacker-created terms survived -- 14 of them named after spam
// URLs outright.
func taxonomyRows(t *testing.T, rows []string) {
	t.Helper()
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "term_taxonomy") {
			return rows
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = prev })
}

func taxonomyFindings(t *testing.T, rows []string) []alert.Finding {
	t.Helper()
	taxonomyRows(t, rows)
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	var out []alert.Finding
	for _, f := range checkWPSpamTaxonomy("alice", creds, "wp_") {
		if f.Check == "db_spam_taxonomy" {
			out = append(out, f)
		}
	}
	return out
}

// A term whose name is a URL has no legitimate explanation.
func TestSpamTaxonomy_UrlNamedTerms(t *testing.T) {
	rows := []string{
		"48\tpost_tag\t1\thttps://hellspincasino.pl",
		"49\tpost_tag\t1\thttps://azurslots.at",
		"50\tpost_tag\t1\thttps://22betlk.com",
	}
	got := taxonomyFindings(t, rows)
	if len(got) != 1 {
		t.Fatalf("expected 1 aggregated finding, got %d", len(got))
	}
	if !strings.Contains(got[0].Message, "3 spam taxonomy terms") {
		t.Errorf("finding should report the count, got: %s", got[0].Message)
	}
	if got[0].Severity != alert.High {
		t.Errorf("URL-named taxonomy severity = %v, want High", got[0].Severity)
	}
}

// Gambling and pharma vocabulary in a term name, with no URL.
func TestSpamTaxonomy_KeywordNamedTerms(t *testing.T) {
	rows := []string{
		"47\tcategory\t14\tOnline gambling",
		"44\tcategory\t1\talle nederlandse casinos_nl",
	}
	got := taxonomyFindings(t, rows)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding for keyword-named terms, got %d", len(got))
	}
	if got[0].Severity != alert.Warning {
		t.Errorf("keyword-named taxonomy severity = %v, want Warning", got[0].Severity)
	}
	if !strings.Contains(got[0].Message, "2 spam taxonomy terms") {
		t.Errorf("keyword-named taxonomy count = %q, want 2", got[0].Message)
	}
}

// Database rows use mysql batch escaping. Leading whitespace must be decoded
// before the URL check or a term named "\nhttps://..." bypasses the anchor.
func TestSpamTaxonomy_BatchEscapedWhitespaceBeforeURL(t *testing.T) {
	rows := []string{"48\tpost_tag\t1\t\\nhttps://hellspincasino.pl"}
	got := taxonomyFindings(t, rows)
	if len(got) != 1 || got[0].Severity != alert.High {
		t.Fatalf("batch-escaped URL term produced %v, want one High finding", got)
	}
}

func TestSpamTaxonomy_ControlCharactersAreQuotedInDetails(t *testing.T) {
	got := taxonomyFindings(t, []string{"48\tpost_tag\t1\tCasino\\nInjected"})
	if len(got) != 1 {
		t.Fatalf("control-character term produced %d findings, want 1", len(got))
	}
	if strings.Contains(got[0].Details, "Casino\nInjected") ||
		!strings.Contains(got[0].Details, `Casino\nInjected`) {
		t.Errorf("taxonomy details did not quote control characters: %q", got[0].Details)
	}
}

func TestSpamTaxonomy_QueryFiltersCandidatesBeforeRowLimit(t *testing.T) {
	prev := runMySQLQuery
	var query string
	runMySQLQuery = func(_ wpDBCreds, q string) []string {
		query = q
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	checkWPSpamTaxonomy("alice", wpDBCreds{dbName: "wp"}, "wp_")
	if !strings.Contains(query, " REGEXP ") {
		t.Errorf("taxonomy query does not filter suspicious candidates before LIMIT: %s", query)
	}
	wantLimit := maxTaxonomyRowsScanned + 1
	if !strings.Contains(query, "LIMIT "+strconv.Itoa(wantLimit)) {
		t.Errorf("taxonomy query limit = %q, want look-ahead limit %d", query, wantLimit)
	}
}

func TestSpamTaxonomy_TruncatedCandidateCountIsReportedAsFloor(t *testing.T) {
	rows := make([]string, 0, maxTaxonomyRowsScanned+1)
	for i := 0; i <= maxTaxonomyRowsScanned; i++ {
		rows = append(rows, fmt.Sprintf("%d\tpost_tag\t1\thttps://spam-%d.example", i+1, i+1))
	}
	taxonomyRows(t, rows)
	ctx, incomplete := withIncompleteCheckCollector(t.Context())
	got := checkWPSpamTaxonomy("alice", wpDBCreds{dbName: "wp", queryCtx: ctx}, "wp_")
	if len(got) != 1 {
		t.Fatalf("truncated taxonomy produced %d findings, want 1", len(got))
	}
	want := fmt.Sprintf("at least %d spam taxonomy terms", maxTaxonomyRowsScanned)
	if !strings.Contains(got[0].Message, want) {
		t.Errorf("truncated taxonomy count = %q, want %q", got[0].Message, want)
	}
	if !incomplete.contains("db_content") {
		t.Error("taxonomy row limit did not mark the database scan incomplete")
	}
}

func TestSpamTaxonomy_DetailsBoundAttackerControlledSamples(t *testing.T) {
	rows := make([]string, 0, maxTaxonomyRowsScanned)
	for i := 0; i < maxTaxonomyRowsScanned; i++ {
		rows = append(rows, fmt.Sprintf("%d\tpost_tag\t1\thttps://spam-%03d.example/%s",
			i+1, i+1, strings.Repeat("x", 150)))
	}
	got := taxonomyFindings(t, rows)
	if len(got) != 1 {
		t.Fatalf("large taxonomy sample produced %d findings, want 1", len(got))
	}
	if !strings.Contains(got[0].Message, fmt.Sprintf("%d spam taxonomy terms", maxTaxonomyRowsScanned)) {
		t.Errorf("large taxonomy sample lost the full count: %q", got[0].Message)
	}
	if !strings.Contains(got[0].Details, "showing 10 of 500") {
		t.Errorf("large taxonomy details do not disclose the sample bound: %q", got[0].Details)
	}
	if len(got[0].Details) > 5000 {
		t.Errorf("large taxonomy details are unbounded: %d bytes", len(got[0].Details))
	}
}

func TestSpamTaxonomy_ScansMultisiteSecondaryTerms(t *testing.T) {
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		switch {
		case strings.Contains(query, "FROM wp_blogs"):
			return []string{"2"}
		case strings.Contains(query, "JOIN wp_2_term_taxonomy"):
			return []string{"48\tpost_tag\t1\thttps://hellspincasino.pl"}
		default:
			return nil
		}
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	findings := scanMultisiteSecondaryBlogs(t.Context(), "alice", wpDBCreds{dbName: "network"}, "wp_")
	for _, finding := range findings {
		if finding.Check == "db_spam_taxonomy" && strings.Contains(finding.Details, "Table prefix: wp_2_") {
			return
		}
	}
	t.Fatalf("secondary blog taxonomy was not reported: %+v", findings)
}

// The business's own taxonomy must stay quiet. These are the real terms from
// the compromised site, which had to survive the cleanup intact.
func TestSpamTaxonomy_LegitimateTermsStayQuiet(t *testing.T) {
	rows := []string{
		"1\tcategory\t63\tSisteme Firestone",
		"24\tre_projects_category\t34\tHidroizolatii",
		"43\tcategory\t427\tuncategorized",
		"29\tpost_tag\t0\thidroizolatie acoperis",
		"26\tnav_menu\t7\tMain menu",
		"39\twpcode_type\t7\tphp",
		// A dotted name that is not a domain: a legitimate technology category.
		"70\tcategory\t3\tNode.js",
		// Ordinary editorial categories.
		"71\tcategory\t9\tNews & Updates",
	}
	if got := taxonomyFindings(t, rows); len(got) != 0 {
		t.Errorf("legitimate taxonomy produced findings: %d (%v)", len(got), got)
	}
}

func TestSpamTaxonomy_MalformedRows(t *testing.T) {
	rows := []string{"", "1", "2\tcategory", "\t\t\t", "x\tcategory\ty\t"}
	taxonomyRows(t, rows)
	ctx, incomplete := withIncompleteCheckCollector(t.Context())
	if got := checkWPSpamTaxonomy("alice", wpDBCreds{dbName: "wp", queryCtx: ctx}, "wp_"); len(got) != 0 {
		t.Errorf("malformed rows produced findings: %d", len(got))
	}
	if !incomplete.contains("db_content") {
		t.Error("malformed taxonomy rows did not mark the database scan incomplete")
	}
}
