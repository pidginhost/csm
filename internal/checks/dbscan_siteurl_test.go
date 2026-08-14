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
		if f.Check == "db_siteurl_hijack" || f.Check == "db_siteurl_invalid" {
			msgs = append(msgs, f.Message+" | "+f.Details)
		}
	}
	return msgs
}

func siteurlCheckNames(t *testing.T, rows []string) []string {
	t.Helper()
	withMockCoreOptions(t, rows)
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	var names []string
	for _, f := range checkWPOptions("alice", creds, "wp_") {
		if strings.HasPrefix(f.Check, "db_siteurl_") {
			names = append(names, f.Check)
		}
	}
	return names
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

func TestCheckWPOptions_MalformedAddressIsAlertOnly(t *testing.T) {
	got := siteurlCheckNames(t, []string{
		"siteurl\thttps://slow.destinyfernandi.com/hos?/pret.js?l=1",
	})
	if len(got) != 1 || got[0] != "db_siteurl_invalid" {
		t.Fatalf("malformed address must not enter hijack auto-response, got %v", got)
	}
}

func TestCheckWPOptions_FlagsSiteurlPointingAtScript(t *testing.T) {
	for _, value := range []string{
		"https://cdn.example.net/loader.js",
		"https://cdn.example.net/loader.phtml",
		"https://cdn.example.net/loader.aspx",
	} {
		if got := siteurlFindings(t, []string{"siteurl\t" + value}); len(got) != 1 {
			t.Errorf("siteurl resolving to script %q must report, got %v", value, got)
		}
	}
}

func TestCheckWPOptions_FlagsNonAbsoluteSiteurl(t *testing.T) {
	got := siteurlFindings(t, []string{"siteurl\tdata:text/html;base64,PHNjcmlwdD4="})
	if len(got) != 1 {
		t.Fatalf("a siteurl that is not an http(s) URL must report, got %v", got)
	}
}

func TestCheckWPOptions_FlagsMalformedHTTPAuthorities(t *testing.T) {
	for _, value := range []string{
		"https://:8443/blog",
		"https://example.com:65536/blog",
	} {
		if got := siteurlFindings(t, []string{"siteurl\t" + value}); len(got) != 1 {
			t.Errorf("malformed siteurl %q must report, got %v", value, got)
		}
	}
}

func TestCheckWPOptions_DecodesMySQLBatchEscapesBeforeParsing(t *testing.T) {
	for _, row := range []string{
		"siteurl\thttps://example.com/\\nloader",
		"siteurl\thttps://example.com\\\\loader",
		"siteurl\thttps://example.com/path\\\\loader",
	} {
		if got := siteurlFindings(t, []string{row}); len(got) != 1 {
			t.Errorf("batch-escaped malformed siteurl %q must report, got %v", row, got)
		}
	}
}

func TestCheckWPOptions_NormalizesCaseVariantOptionNames(t *testing.T) {
	got := siteurlFindings(t, []string{"SiteURL\thttps://example.com/path?loader.js"})
	if len(got) != 1 {
		t.Fatalf("a poisoned case-variant siteurl must report, got %v", got)
	}
	if !strings.Contains(got[0], "siteurl =") {
		t.Fatalf("finding must preserve a verifiable canonical option name, got %q", got[0])
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
	got := siteurlCheckNames(t, []string{"siteurl\thttps://example.com/<script>x</script>"})
	if len(got) != 1 || got[0] != "db_siteurl_hijack" {
		t.Fatalf("injected markup must retain hijack auto-response, got %v", got)
	}
}

// admin_email shares the query but is not a URL, so it must never be judged
// by URL shape.
func TestCheckWPOptions_IgnoresAdminEmail(t *testing.T) {
	if got := siteurlFindings(t, []string{"admin_email\tadmin@example.com"}); len(got) != 0 {
		t.Fatalf("admin_email must not be treated as a site URL: %v", got)
	}
}
