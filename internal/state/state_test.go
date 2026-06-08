package state

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestSetLatestFindingsKeepsDistinctDetailsVariants(t *testing.T) {
	store := &Store{path: t.TempDir()}
	findings := []alert.Finding{
		{Check: "test", Message: "same", Details: "one"},
		{Check: "test", Message: "same", Details: "two"},
	}

	store.SetLatestFindings(findings)
	got := store.LatestFindings()
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct findings, got %d", len(got))
	}
}

func TestHTTPAbuseFindingDoesNotRealertWhenOnlyCountsChange(t *testing.T) {
	store := &Store{
		path:    t.TempDir(),
		entries: make(map[string]*Entry),
	}

	first := alert.Finding{
		Check:   "wp_login_bruteforce",
		Message: "WordPress brute force from 203.0.113.40: 12 attempts",
		Details: "Aggregated across 272 domlog files",
	}
	store.Update([]alert.Finding{first})

	changedCount := alert.Finding{
		Check:   "wp_login_bruteforce",
		Message: "WordPress brute force from 203.0.113.40: 31 attempts",
		Details: "Aggregated across 120 domlog files",
	}
	if got := store.FilterNew([]alert.Finding{changedCount}); len(got) != 0 {
		t.Fatalf("changed HTTP count re-alerted: %+v", got)
	}
}

func TestIsSuppressedMatchesExtractedMessagePath(t *testing.T) {
	store := &Store{path: t.TempDir()}
	finding := alert.Finding{
		Check:   "malware",
		Message: "Suspicious file found: /home/user/public_html/bad.php",
	}
	rules := []SuppressionRule{{
		Check:       "malware",
		PathPattern: "/home/user/public_html/*",
	}}

	if !store.IsSuppressed(finding, rules) {
		t.Fatal("expected suppression to match extracted path")
	}
}

func TestIsSuppressedMatchesExtractedDetailsPath(t *testing.T) {
	store := &Store{path: t.TempDir()}
	finding := alert.Finding{
		Check:   "perf_wp_cron",
		Message: "WP-Cron not disabled for alice",
		Details: "File: /home/alice/public_html/wp-config.php - add define('DISABLE_WP_CRON', true);",
	}
	rules := []SuppressionRule{{
		Check:       "perf_wp_cron",
		PathPattern: "/home/alice/public_html/wp-config.php",
	}}

	if !store.IsSuppressed(finding, rules) {
		t.Fatal("expected suppression to match path extracted from details")
	}
}

// TestMarkAlertedResetsDedupWindow guards the long-lived-finding dedup bug:
// once AlertSent ages past 24h, every dispatched re-emit must reset the
// timestamp so subsequent ticks within the next 24h are suppressed again.
// Without MarkAlerted, FilterNew re-emits forever on every tick, which is
// what produced hourly false-positive emails for sticky findings like
// db_rogue_admin (a recently-created legitimate WP admin sits in the 7-day
// query window for a week).
func TestMarkAlertedResetsDedupWindow(t *testing.T) {
	store := &Store{
		path:    t.TempDir(),
		entries: make(map[string]*Entry),
	}
	finding := alert.Finding{
		Check:   "db_rogue_admin",
		Message: "New WordPress admin account: alice",
		Details: "Database: site_wp\nUser ID: 6",
	}
	findings := []alert.Finding{finding}

	store.Update(findings)
	key := findingKey(finding)
	store.entries[key].AlertSent = time.Now().Add(-25 * time.Hour)

	if got := store.FilterNew(findings); len(got) != 1 {
		t.Fatalf("expected re-emit past 24h boundary, got %d", len(got))
	}

	store.Update(findings)
	store.MarkAlerted(findings)

	if got := store.FilterNew(findings); len(got) != 0 {
		t.Fatalf("expected suppression after MarkAlerted resets the window, got %d re-emits", len(got))
	}
}
