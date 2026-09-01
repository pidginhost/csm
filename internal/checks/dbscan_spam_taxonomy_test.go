package checks

import (
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
	if !strings.Contains(got[0].Message, "3") {
		t.Errorf("finding should report the count, got: %s", got[0].Message)
	}
}

// Gambling and pharma vocabulary in a term name, with no URL.
func TestSpamTaxonomy_KeywordNamedTerms(t *testing.T) {
	rows := []string{
		"47\tcategory\t14\tOnline gambling",
		"44\tcategory\t1\talle nederlandse casinos_nl",
	}
	if got := taxonomyFindings(t, rows); len(got) != 1 {
		t.Fatalf("expected 1 finding for keyword-named terms, got %d", len(got))
	}
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
	if got := taxonomyFindings(t, rows); len(got) != 0 {
		t.Errorf("malformed rows produced findings: %d", len(got))
	}
}
