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
	if !strings.Contains(msg, "at least") {
		t.Errorf("truncated sample must report a floor, got: %s", msg)
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
	for _, f := range checkWPPosts("alice", creds, "wp_") {
		if f.Check == "db_spam_injection" && strings.Contains(f.Message, "at least") {
			t.Errorf("exact count must not be hedged, got: %s", f.Message)
		}
	}
}
