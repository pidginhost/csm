package checks

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// Cloak logic stored in the database.
//
// A cloak has to decide what to serve on every request, which means the page
// must not be cached. Stored code that disables caching and, in the same
// snippet, looks for a search-engine crawler is serving one page to the index
// and another to visitors.
//
// Neither half is evidence on its own, which is why both are required: caching
// plugins define these constants from their own files as a matter of course,
// and reading the user agent is ordinary. It is a stored snippet doing both
// that has no innocent reading -- the snippet is not the caching plugin, and it
// has no reason to care whether the visitor is Googlebot.

// cacheDefeatFlag and wpCacheDisabled match a stored define() that stops the
// request being cached. WP_CACHE is separate because it is only a defeat when
// it is being switched off; a site enabling caching writes the same constant.
var (
	cacheDefeatFlag = regexp.MustCompile(
		`(?i)define\s*\(\s*['"](DONOTCACHEPAGE|DONOTCACHEOBJECT|DONOTCACHEDB)['"]`)
	wpCacheDisabled = regexp.MustCompile(
		`(?i)define\s*\(\s*['"](WP_CACHE)['"]\s*,\s*(?:false|0|null)\s*\)`)
)

// crawlerUserAgent matches the crawlers a doorway kit cares about. The list is
// the set worth cloaking for: the engines that index and rank, plus the SEO
// crawlers kits hide from to stay out of backlink reports.
var crawlerUserAgent = regexp.MustCompile(
	`(?i)\b(googlebot|bingbot|msnbot|yandex(?:bot)?|baiduspider|duckduckbot|slurp|` +
		`applebot|sogou|exabot|facebot|ia_archiver|ahrefsbot|semrushbot|mj12bot|dotbot)\b`)

// storedCloakComponents returns the cache-defeat and crawler-detection markers
// found in one stored snippet.
func storedCloakComponents(code []byte) (cacheDefeat, crawler []string) {
	seenCache := make(map[string]bool)
	for _, re := range []*regexp.Regexp{cacheDefeatFlag, wpCacheDisabled} {
		cacheDefeat = appendCapturedNames(cacheDefeat, seenCache, re, code, strings.ToUpper)
	}
	sort.Strings(cacheDefeat)
	return cacheDefeat, appendCapturedNames(nil, make(map[string]bool), crawlerUserAgent, code, strings.ToLower)
}

// appendCapturedNames collects the first capture group of each match, so the
// finding names the constant or crawler rather than the surrounding syntax.
func appendCapturedNames(out []string, seen map[string]bool, re *regexp.Regexp, code []byte, canonical func(string) string) []string {
	for _, m := range re.FindAllSubmatch(code, maxStoredCloakMatches) {
		if len(m) < 2 {
			continue
		}
		name := canonical(strings.TrimSpace(string(m[1])))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// maxStoredCloakMatches bounds the scan of one snippet. The finding names a
// handful of markers; a snippet repeating one thousands of times says nothing
// more than the first few do.
const maxStoredCloakMatches = 64

// storedCloakFinding reports a stored snippet that both defeats caching and
// looks for a crawler, or nil when only one half is present.
func storedCloakFinding(user string, creds wpDBCreds, prefix string, row storedCodeRow) *alert.Finding {
	cacheDefeat, crawler := storedCloakComponents(row.code)
	if len(cacheDefeat) == 0 || len(crawler) == 0 {
		return nil
	}

	// Only a published snippet runs. A draft still documents the intent.
	severity := alert.Warning
	if row.status == "publish" {
		severity = alert.High
	}

	return &alert.Finding{
		Severity: severity,
		Check:    "db_stored_cloak_logic",
		Message: fmt.Sprintf("Stored PHP snippet %s (%s) serves crawlers differently from visitors (account: %s)",
			row.id, row.status, user),
		Details: dbContentFindingDetails(creds.dbName, prefix,
			fmt.Sprintf("Snippet %s is stored in %sposts, so no filesystem scan reads it.", row.id, prefix),
			"It disables caching for the request and, in the same snippet, tests the "+
				"visitor against a search-engine crawler. Cloaks need both: the decision "+
				"is per request, so the page must not be served from cache. A caching "+
				"plugin sets these constants from its own files and has no reason to look "+
				"for Googlebot.",
			"Cache defeat: "+strings.Join(cacheDefeat, ", "),
			"Crawlers named: "+strings.Join(crawler, ", ")),
	}
}

// storedCloakNote adds the cloak components to a snippet that already matched a
// signature, rather than raising a second finding about the same row.
func storedCloakNote(cacheDefeat, crawler []string) string {
	if len(cacheDefeat) == 0 || len(crawler) == 0 {
		return ""
	}
	return fmt.Sprintf("\nIt also cloaks: caching is disabled for the request (%s) "+
		"while the visitor is tested against %s, so what a crawler is served is "+
		"not what a visitor sees.",
		strings.Join(cacheDefeat, ", "), strings.Join(crawler, ", "))
}
