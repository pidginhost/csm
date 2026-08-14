package checks

import (
	"strings"
	"testing"
)

// withMockCoreOptions serves rows for the siteurl/home/admin_email query only.
func withMockCoreOptions(t *testing.T, rows []string) {
	t.Helper()
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "admin_email") {
			return rows
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = prev })
}

func siteurlFindings(t *testing.T, rows []string) []string {
	t.Helper()
	withMockCoreOptions(t, rows)
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	var msgs []string
	for _, f := range checkWPOptions("alice", creds, "wp_") {
		if f.Check == "db_siteurl_hijack" {
			msgs = append(msgs, f.Message+" | "+f.Details)
		}
	}
	return msgs
}

// Production case: an abandoned install had siteurl rewritten so every asset
// URL WordPress builds loads a remote script. It carries no eval( and no
// <script, which is all the detector looked for, so it was never reported.
func TestCheckWPOptions_FlagsSiteurlWithQueryString(t *testing.T) {
	got := siteurlFindings(t, []string{
		"siteurl\thttps://slow.destinyfernandi.com/hos?/pret.js?l=1",
		"home\thttps://slow.destinyfernandi.com/hos?/pret?l=1",
	})
	if len(got) != 2 {
		t.Fatalf("both poisoned options must report, got %d: %v", len(got), got)
	}
}

func TestCheckWPOptions_FlagsSiteurlPointingAtScript(t *testing.T) {
	got := siteurlFindings(t, []string{"siteurl\thttps://cdn.example.net/loader.js"})
	if len(got) != 1 {
		t.Fatalf("a siteurl resolving to a script must report, got %v", got)
	}
}

func TestCheckWPOptions_FlagsNonAbsoluteSiteurl(t *testing.T) {
	got := siteurlFindings(t, []string{"siteurl\tdata:text/html;base64,PHNjcmlwdD4="})
	if len(got) != 1 {
		t.Fatalf("a siteurl that is not an http(s) URL must report, got %v", got)
	}
}

// Every one of these shapes exists on a production host. None may report.
func TestCheckWPOptions_AcceptsOrdinarySiteurls(t *testing.T) {
	for _, value := range []string{
		"https://example.com",
		"https://www.example.com",
		"http://example.com",
		"https://example.com/blog",
		"https://example.com/blog/",
		"http://www.example.com/trailere",
		"https://sub.dev.example.com/caseciorogarla/",
		"https://example.com:8443",
		"https://example.com/WORKZEX",
	} {
		if got := siteurlFindings(t, []string{"siteurl\t" + value}); len(got) != 0 {
			t.Errorf("ordinary siteurl %q reported: %v", value, got)
		}
	}
}

// The original eval()/<script> shapes must keep reporting.
func TestCheckWPOptions_StillFlagsScriptInSiteurl(t *testing.T) {
	got := siteurlFindings(t, []string{"siteurl\thttps://example.com/<script>x</script>"})
	if len(got) != 1 {
		t.Fatalf("injected markup in siteurl must still report, got %v", got)
	}
}

// admin_email shares the query but is not a URL, so it must never be judged
// by URL shape.
func TestCheckWPOptions_IgnoresAdminEmail(t *testing.T) {
	if got := siteurlFindings(t, []string{"admin_email\tadmin@example.com"}); len(got) != 0 {
		t.Fatalf("admin_email must not be treated as a site URL: %v", got)
	}
}
