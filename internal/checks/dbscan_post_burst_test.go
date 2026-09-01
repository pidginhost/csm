package checks

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A spam kit publishes far more in months than the site did in years. That rate
// change needs no keyword list, which matters because the real spam spanned
// German, Czech, Polish, Dutch, French, English and Azerbaijani -- a gambling
// regex matched only 248 of 508 posts, while the publishing history separated
// them perfectly: 17 posts across 2018-2021, then 508 in under a year.
func burstRows(t *testing.T, ageDays, prior, recent int) {
	t.Helper()
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if !strings.Contains(query, "DATEDIFF") {
			return nil
		}
		return []string{fmt.Sprintf("%d\t%d\t%d", ageDays, prior, recent)}
	}
	t.Cleanup(func() { runMySQLQuery = prev })
}

func burstFindings(t *testing.T, ageDays, prior, recent int) []alert.Finding {
	t.Helper()
	burstRows(t, ageDays, prior, recent)
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	var out []alert.Finding
	for _, f := range checkWPPostVolumeBurst("alice", creds, "wp_") {
		if f.Check == "db_post_volume_burst" {
			out = append(out, f)
		}
	}
	return out
}

// The live shape: a seven-year-old site with 17 posts that suddenly gains 508.
func TestPostBurst_SpamFloodIsReported(t *testing.T) {
	if got := burstFindings(t, 2900, 17, 508); len(got) != 1 {
		t.Fatalf("expected 1 burst finding, got %d", len(got))
	}
}

// A site that has always published steadily must stay quiet, however large it
// is -- volume alone is not the signal, the change in rate is.
func TestPostBurst_SteadyPublisherStaysQuiet(t *testing.T) {
	if got := burstFindings(t, 2900, 4000, 300); len(got) != 0 {
		t.Errorf("steady publisher produced findings: %d", len(got))
	}
}

// A young site has no history to compare against; its first burst of posts is
// ordinary launch activity, not a compromise.
func TestPostBurst_YoungSiteStaysQuiet(t *testing.T) {
	if got := burstFindings(t, 60, 2, 400); len(got) != 0 {
		t.Errorf("young site produced findings: %d", len(got))
	}
}

// A modest uptick on a quiet site is normal editorial behaviour.
func TestPostBurst_SmallUptickStaysQuiet(t *testing.T) {
	if got := burstFindings(t, 2900, 4, 30); len(got) != 0 {
		t.Errorf("small uptick produced findings: %d", len(got))
	}
}

// A site with genuinely no prior posts must not divide by zero or fire on a
// first publishing run.
func TestPostBurst_NoPriorHistory(t *testing.T) {
	if got := burstFindings(t, 2900, 0, 500); len(got) != 1 {
		t.Fatalf("aged site with no prior posts and a 500-post flood: got %d, want 1", len(got))
	}
	if got := burstFindings(t, 30, 0, 500); len(got) != 0 {
		t.Errorf("young site with no history produced findings: %d", len(got))
	}
}

func TestPostBurst_MalformedRows(t *testing.T) {
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if !strings.Contains(query, "DATEDIFF") {
			return nil
		}
		return []string{"", "1", "x\ty\tz", "\t\t", "2900\t17"}
	}
	t.Cleanup(func() { runMySQLQuery = prev })
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	if got := checkWPPostVolumeBurst("alice", creds, "wp_"); len(got) != 0 {
		t.Errorf("malformed rows produced findings: %d", len(got))
	}
}
