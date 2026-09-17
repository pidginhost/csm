package checks

import (
	"fmt"
	"strings"
	"testing"
)

// A per-pattern LIMIT bounds how many rows the scan pulls back. When that cap
// is reached the finding must say the count is a floor, not a total: an
// operator triaging "3 posts" deprioritises what triaging "at least 200"
// escalates, and on a real compromise the true figure was 508.
func TestSpamScale_TruncatedSampleIsReportedAsFloor(t *testing.T) {
	prev := runMySQLQuery
	// Return exactly the per-pattern cap for the first spam pattern, each row
	// carrying cloaked-spam context so it survives the context filter.
	// Shape taken from the live lalimanro injection: an off-screen container
	// wrapping an outbound pharmacy link.
	cloaked := `<div style="position:absolute;left:-12623px;width:1000px"><a href="https://farmacia.example/produs/viagra/">Viagra</a></div>`
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if !strings.Contains(query, "pattern_index") || !strings.Contains(query, "post_content LIKE") {
			return nil
		}
		rows := make([]string, 0, dbSpamSampleLimit)
		for i := 0; i < dbSpamSampleLimit; i++ {
			rows = append(rows, fmt.Sprintf("0\t%d\t%s", 1000+i, cloaked))
		}
		return rows
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	var msg string
	for _, f := range checkWPPosts("alice", creds, "wp_") {
		if f.Check == "db_spam_injection" {
			msg = f.Message
		}
	}
	if msg == "" {
		t.Fatal("no db_spam_injection finding produced")
	}
	want := fmt.Sprintf("at least %d posts", dbSpamSampleLimit)
	if !strings.Contains(msg, want) {
		t.Errorf("truncated sample must report %q, got: %s", want, msg)
	}
}

// Below the cap the count is exact and must not be hedged, or every finding
// reads as uncertain.
func TestSpamScale_UntruncatedSampleIsExact(t *testing.T) {
	prev := runMySQLQuery
	// Shape taken from the live lalimanro injection: an off-screen container
	// wrapping an outbound pharmacy link.
	cloaked := `<div style="position:absolute;left:-12623px;width:1000px"><a href="https://farmacia.example/produs/viagra/">Viagra</a></div>`
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if !strings.Contains(query, "pattern_index") || !strings.Contains(query, "post_content LIKE") {
			return nil
		}
		return []string{"0\t1001\t" + cloaked, "0\t1002\t" + cloaked}
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	var msg string
	for _, f := range checkWPPosts("alice", creds, "wp_") {
		if f.Check == "db_spam_injection" {
			msg = f.Message
		}
	}
	if msg == "" {
		t.Fatal("no db_spam_injection finding produced")
	}
	if !strings.Contains(msg, "(2 posts,") || strings.Contains(msg, "at least") {
		t.Errorf("exact sample must report 2 posts without a hedge, got: %s", msg)
	}
}

func TestSpamScale_MalformedCappedSampleStaysIncompleteAndHedged(t *testing.T) {
	prev := runMySQLQuery
	cloaked := `<div style="position:absolute;left:-12623px;width:1000px"><a href="https://farmacia.example/produs/viagra/">Viagra</a></div>`
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if !strings.Contains(query, "pattern_index") || !strings.Contains(query, "post_content LIKE") {
			return nil
		}
		rows := make([]string, 0, dbSpamSampleLimit)
		for i := 0; i < dbSpamSampleLimit-1; i++ {
			rows = append(rows, fmt.Sprintf("0\t%d\t%s", 1000+i, cloaked))
		}
		return append(rows, "0\tmalformed")
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	ctx, incomplete := withIncompleteCheckCollector(t.Context())
	creds := wpDBCreds{dbName: "wp", queryCtx: ctx}
	var msg string
	for _, finding := range checkWPPosts("alice", creds, "wp_") {
		if finding.Check == "db_spam_injection" {
			msg = finding.Message
		}
	}
	want := fmt.Sprintf("at least %d posts", dbSpamSampleLimit-1)
	if !strings.Contains(msg, want) {
		t.Errorf("malformed capped sample must report %q, got: %s", want, msg)
	}
	if !incomplete.contains("db_content") {
		t.Error("malformed spam row did not mark the database scan incomplete")
	}
}

// Each spam pattern is a separate finding with its own keyword in the message.
// Pinning the identity must not merge them: an operator who dismisses the
// pharmacy row would otherwise lose the gambling one with it.
func TestSpamScale_EachKeywordKeepsItsOwnIdentity(t *testing.T) {
	prev := runMySQLQuery
	cloaked := map[int]string{}
	for i, sp := range dbSpamPatterns {
		cloaked[i] = fmt.Sprintf(
			`<div style="position:absolute;left:-12623px;width:1000px"><a href="https://spam.example/%s/">%s</a></div>`,
			sp.keyword, sp.keyword)
	}
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if !strings.Contains(query, "pattern_index") || !strings.Contains(query, "post_content LIKE") {
			return nil
		}
		var rows []string
		for i := range dbSpamPatterns {
			rows = append(rows, fmt.Sprintf("%d\t%d\t%s", i, 1000+i, cloaked[i]))
		}
		return rows
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	keys := map[string]string{}
	for _, f := range checkWPPosts("alice", creds, "wp_") {
		if f.Check != "db_spam_injection" {
			continue
		}
		if prevMsg, clash := keys[f.Key()]; clash {
			t.Errorf("two spam keywords share one identity %q:\n %s\n %s", f.Key(), prevMsg, f.Message)
		}
		keys[f.Key()] = f.Message
	}
	if len(keys) != len(dbSpamPatterns) {
		t.Fatalf("got %d distinct findings, want one for each of %d spam patterns", len(keys), len(dbSpamPatterns))
	}
}
