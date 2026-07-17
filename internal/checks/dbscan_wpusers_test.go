package checks

import (
	"strings"
	"testing"
)

// withMockMySQLRows redirects runMySQLQuery for the test. The fake serves
// rows only for the recent-admin query (identified by its DATE_SUB filter);
// every other query returns nothing.
func withMockMySQLRows(t *testing.T, adminRows []string) {
	t.Helper()
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "DATE_SUB") {
			return adminRows
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = prev })
}

func rogueAdminFindings(t *testing.T, adminRows []string) int {
	t.Helper()
	withMockMySQLRows(t, adminRows)
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	count := 0
	for _, f := range checkWPUsers("alice", creds, "wp_") {
		if f.Check == "db_rogue_admin" {
			count++
		}
	}
	return count
}

func TestCheckWPUsersSuppressesInstallEraAdmin(t *testing.T) {
	// The installer-created admin registers at the exact moment the users
	// table comes to life: user_registered == MIN(user_registered).
	rows := []string{
		"1\tadmin_x8f2k\tadmin@example.com\t2026-07-14 16:21:56\t2026-07-14 16:21:56",
	}
	if got := rogueAdminFindings(t, rows); got != 0 {
		t.Fatalf("install-era admin produced %d db_rogue_admin findings, want 0", got)
	}
}

func TestCheckWPUsersSuppressesAdminWithinInstallGrace(t *testing.T) {
	// A second admin created moments after install (multi-admin setup
	// wizards) is part of the same install, not a takeover.
	rows := []string{
		"2\tsetupadmin\tsetup@example.com\t2026-07-14 16:30:00\t2026-07-14 16:21:56",
	}
	if got := rogueAdminFindings(t, rows); got != 0 {
		t.Fatalf("install-grace admin produced %d findings, want 0", got)
	}
}

func TestCheckWPUsersFlagsAdminAddedAfterInstallGrace(t *testing.T) {
	rows := []string{
		"2\twebadmin\tagency@example.com\t2026-07-16 17:03:58\t2026-07-14 16:21:56",
	}
	if got := rogueAdminFindings(t, rows); got != 1 {
		t.Fatalf("post-install admin produced %d findings, want 1", got)
	}
}

func TestCheckWPUsersFlagsRecentAdminOnEstablishedSite(t *testing.T) {
	rows := []string{
		"57\thelpdesk\tattacker@example.com\t2026-07-16 09:00:00\t2019-03-02 08:11:05",
	}
	if got := rogueAdminFindings(t, rows); got != 1 {
		t.Fatalf("recent admin on an established site produced %d findings, want 1", got)
	}
}

func TestCheckWPUsersFlagsWhenTimestampsUnparseable(t *testing.T) {
	// Fail open: a row whose timestamps cannot be parsed must still alert.
	rows := []string{
		"3\tmystery\tx@example.com\tnot-a-date\talso-not-a-date",
		"4\tmystery2\ty@example.com\t2026-07-16 09:00:00\t",
	}
	if got := rogueAdminFindings(t, rows); got != 2 {
		t.Fatalf("unparseable timestamps produced %d findings, want 2 (fail-open)", got)
	}
}
