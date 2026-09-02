package checks

import "testing"

// The long-list gates exist for operator blocklists: many scraper UAs OR'd
// together and sent to a sinkhole. A cloak that lists several search-engine
// crawlers and redirects them to a doorway is not a blocklist, however many
// crawlers it names: nobody blocks Googlebot, Bingbot, Yandex and Baidu at
// once. Such a list must fall through to the paired-rule check.
func TestDetectorUserAgentCloak_SearchCrawlerListRedirect(t *testing.T) {
	dir := t.TempDir()
	body := "RewriteCond %{HTTP_USER_AGENT} (googlebot|bingbot|yandex|baiduspider) [NC]\n" +
		"RewriteRule ^(.*)$ https://doorway-casino.com/$1 [R=302,L]\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_user_agent_cloak"); got != 1 {
		t.Fatalf("ua_cloak matches = %d, want 1 for a four-crawler doorway redirect", got)
	}
}

func TestDetectorUserAgentCloak_SearchCrawlerChainRedirect(t *testing.T) {
	dir := t.TempDir()
	body := "RewriteCond %{HTTP_USER_AGENT} googlebot [NC,OR]\n" +
		"RewriteCond %{HTTP_USER_AGENT} bingbot [NC,OR]\n" +
		"RewriteCond %{HTTP_USER_AGENT} yandex [NC,OR]\n" +
		"RewriteCond %{HTTP_USER_AGENT} duckduckbot [NC]\n" +
		"RewriteRule ^(.*)$ https://doorway-casino.com/$1 [R=302,L]\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_user_agent_cloak"); got == 0 {
		t.Fatal("ua_cloak matches = 0, want the four-line search-crawler chain reported")
	}
}

// A long list of search crawlers that only forbids is still defensive.
func TestDetectorUserAgentCloak_SearchCrawlerListForbidStaysQuiet(t *testing.T) {
	dir := t.TempDir()
	body := "RewriteCond %{HTTP_USER_AGENT} (googlebot|bingbot|yandex|baiduspider) [NC]\n" +
		"RewriteRule ^(.*)$ - [F,L]\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_user_agent_cloak"); got != 0 {
		t.Fatalf("ua_cloak matches = %d, want 0 for a forbid rule", got)
	}
}
