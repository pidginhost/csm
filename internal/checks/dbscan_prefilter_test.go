package checks

import (
	"strings"
	"testing"
)

// The SQL pre-filter for script loaders in wp_options demanded the literal
// "src=" while the Go extractor accepts "src = " with spaces, so a loader
// written with spaces was never even fetched for classification.
func TestWPOptionsScriptPrefilterDoesNotRequireLiteralSrcEquals(t *testing.T) {
	prev := runMySQLQuery
	t.Cleanup(func() { runMySQLQuery = prev })
	var queries []string
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		queries = append(queries, query)
		return nil
	}
	checkWPOptions("alice", wpDBCreds{dbName: "alice_wp"}, "wp_")

	var prefilter string
	for _, q := range queries {
		// Path 1 is the any-option loader scan; Path 2 (core options) has
		// its own IN (...) filter and no src requirement.
		if strings.Contains(q, "<script") && strings.Contains(q, "options") && !strings.Contains(q, "option_name IN") {
			prefilter = q
		}
	}
	if prefilter == "" {
		t.Fatalf("no script pre-filter query issued: %v", queries)
	}
	if strings.Contains(prefilter, "src=") {
		t.Fatalf("pre-filter still requires a literal src=: %s", prefilter)
	}
	if !strings.Contains(prefilter, "%src%") {
		t.Fatalf("pre-filter does not match src with surrounding whitespace: %s", prefilter)
	}
}
