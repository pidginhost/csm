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

func TestCheckWPUsersDescribesMissingRegistrationTime(t *testing.T) {
	withMockMySQLRows(t, []string{
		"3\tmystery\tx@example.com\tNULL\t2026-07-14 16:21:56",
	})
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	findings := checkWPUsers("alice", creds, "wp_")
	if len(findings) != 1 {
		t.Fatalf("missing registration timestamp produced %d findings, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Message, "missing or invalid registration timestamp") {
		t.Fatalf("missing registration timestamp has misleading message %q", findings[0].Message)
	}
}

func TestWPInstallEraAdminGraceBoundaries(t *testing.T) {
	first := "2026-07-14 16:21:56"
	tests := []struct {
		name       string
		registered string
		want       bool
	}{
		{name: "before first user", registered: "2026-07-14 16:21:55", want: false},
		{name: "at grace limit", registered: "2026-07-14 16:36:56", want: true},
		{name: "after grace limit", registered: "2026-07-14 16:36:57", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wpInstallEraAdmin(tt.registered, first); got != tt.want {
				t.Fatalf("wpInstallEraAdmin(%q, %q) = %v, want %v", tt.registered, first, got, tt.want)
			}
		})
	}
}

func recentAdminQuery(t *testing.T) string {
	t.Helper()
	prev := runMySQLQuery
	var queryText string
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "DATE_SUB") {
			queryText = query
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	_ = checkWPUsers("alice", creds, "wp_")
	return queryText
}

func TestCheckWPUsersIncludesMissingRegistrationTimes(t *testing.T) {
	query := recentAdminQuery(t)

	missingBaseline := "CASE WHEN COUNT(*) <> COUNT(user_registered) " +
		"THEN NULL ELSE MIN(user_registered) END"
	if !strings.Contains(query, missingBaseline) {
		t.Fatalf("recent-admin query ignores missing timestamps when deriving the install marker: %q", query)
	}
	if !strings.Contains(query, "u.user_registered IS NULL") ||
		!strings.Contains(query, "CAST(u.user_registered AS CHAR) = '0000-00-00 00:00:00'") {
		t.Fatalf("recent-admin query excludes missing registration timestamps: %q", query)
	}
	missingOrder := "ORDER BY (u.user_registered IS NULL OR " +
		"CAST(u.user_registered AS CHAR) = '0000-00-00 00:00:00') DESC"
	if !strings.Contains(query, missingOrder) {
		t.Fatalf("recent-admin query does not prioritize missing timestamps before its limit: %q", query)
	}
}

func TestCheckWPUsersPrioritizesNewestAdminsBeforeLimit(t *testing.T) {
	query := recentAdminQuery(t)

	orderAt := strings.Index(query, "u.user_registered DESC")
	limitAt := strings.Index(query, "LIMIT 10")
	if orderAt < 0 || limitAt < 0 || orderAt > limitAt {
		t.Fatalf("recent-admin query does not prioritize newest rows before its limit: %q", query)
	}
}

func TestCheckWPUsersDeduplicatesCapabilityMetadataBeforeLimit(t *testing.T) {
	query := recentAdminQuery(t)

	if !strings.Contains(query, "WHERE EXISTS (SELECT 1 FROM wp_usermeta m") {
		t.Fatalf("recent-admin query allows duplicate capability rows to consume its limit: %q", query)
	}
}
