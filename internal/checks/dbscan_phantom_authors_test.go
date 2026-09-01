package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// withMockPhantomAuthorRows serves rows only for the phantom-author query,
// identified by the anti-join it is built around.
func withMockPhantomAuthorRows(t *testing.T, rows []string) {
	t.Helper()
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "IS NULL") && strings.Contains(query, "post_author") {
			return rows
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = prev })
}

func phantomFindings(t *testing.T, rows []string) []alert.Severity {
	t.Helper()
	withMockPhantomAuthorRows(t, rows)
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	var out []alert.Severity
	for _, f := range checkWPPhantomAuthors("alice", creds, "wp_") {
		if f.Check == "db_phantom_post_author" {
			out = append(out, f.Severity)
		}
	}
	return out
}

// A published post whose post_author has no wp_users row is the signature of a
// hidden content farm: the cloak filters those IDs out of admin queries, so the
// posts are invisible in the dashboard but served to visitors and crawlers.
func TestPhantomAuthorsFlagged(t *testing.T) {
	got := phantomFindings(t, []string{"2505\t12062"})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d (%v)", len(got), got)
	}
}

// A large farm is Critical; a stray orphan from a hand-deleted user is not.
func TestPhantomAuthorSeverityScalesWithVolume(t *testing.T) {
	large := phantomFindings(t, []string{"2505\t12062"})
	if len(large) != 1 || large[0] != alert.Critical {
		t.Errorf("large farm: got %v, want one Critical", large)
	}
	small := phantomFindings(t, []string{"91\t2"})
	if len(small) != 1 || small[0] == alert.Critical {
		t.Errorf("small orphan set: got %v, want one non-Critical", small)
	}
}

// Several phantom authors produce one finding each, so an operator sees the
// shape of the farm rather than a single aggregate.
func TestPhantomAuthorsReportedPerAuthor(t *testing.T) {
	got := phantomFindings(t, []string{"2505\t12062", "1705\t6028", "1119\t1083"})
	if len(got) != 3 {
		t.Fatalf("expected 3 findings, got %d (%v)", len(got), got)
	}
}

// post_author 0 is WordPress's own placeholder on some generated rows and never
// indicates a compromise.
func TestPhantomAuthorsIgnoreZeroAuthor(t *testing.T) {
	if got := phantomFindings(t, []string{"0\t14"}); len(got) != 0 {
		t.Errorf("author 0 produced findings: %v", got)
	}
}

// A clean site yields nothing.
func TestPhantomAuthorsCleanSite(t *testing.T) {
	if got := phantomFindings(t, nil); len(got) != 0 {
		t.Errorf("clean site produced findings: %v", got)
	}
}

// Malformed rows must not panic or invent findings. The rows with a valid
// author ID but an unusable count are the ones that reach the count parse;
// without them the author-ID guard absorbs every case and the count guard
// is never exercised.
func TestPhantomAuthorsMalformedRows(t *testing.T) {
	rows := []string{
		"", "notanumber\tx", "5", "\t\t",
		"2505\tnotanumber", // valid author, unparseable count
		"2505\t0",          // valid author, zero count
		"2505\t-3",         // valid author, negative count
	}
	if got := phantomFindings(t, rows); len(got) != 0 {
		t.Errorf("malformed rows produced findings: %v", got)
	}
}
