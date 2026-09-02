package checks

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

// Cloaking infrastructure kept in the options table.
//
// Two shapes, both from doorway kits found on one host:
//
//   - Configuration stored under a digest of the site's own hostname, so the
//     row is unfindable without knowing which site you are looking at, with a
//     base64 layer over the serialized array so its contents do not appear in
//     any search of the table.
//   - One rewrite rule per doorway cluster, routing a numbered sitemap
//     straight into a matching numbered feed, to hand crawlers the generated
//     pages without them appearing in the site's real sitemap.
//
// Neither is code execution. Both are the scaffolding a doorway network needs,
// and both survive the deletion of every spam post.

const (
	// maxCloakOptionBytes bounds one option value. The configuration blobs
	// observed were a few kilobytes; rewrite_rules on a large site is bigger
	// but still far under this.
	maxCloakOptionBytes = 256 * 1024
	// maxCloakOptionRows bounds the digest-named candidates read.
	maxCloakOptionRows = 50
	// maxCloakSamplesShown bounds what the finding names.
	maxCloakSamplesShown = 10
)

// digestOptionName matches an option named by a 32-character hex digest and
// nothing else. WordPress core and plugins name options after what they hold.
var digestOptionName = regexp.MustCompile(`^[0-9a-f]{32}$`)

// phpSerializedArray matches the opening of a PHP-serialized array.
var phpSerializedArray = regexp.MustCompile(`^a:[0-9]{1,10}:\{`)

// numberedSitemapRoute and numberedSitemapFeed are the two halves of the
// doorway routing. Reporting needs both with the same number: real sitemap
// plugins add rewrite rules too, but none of them route sitemap<N>.xml into a
// feed named xmlsitemap<N>.
var (
	numberedSitemapRoute = regexp.MustCompile(`(?i)\bsitemap([0-9]{1,10})\\?\.xml`)
	numberedSitemapFeed  = regexp.MustCompile(`(?i)xmlsitemap([0-9]{1,10})`)
)

// hostnameKeyedOption reports whether an option is cloak configuration keyed
// by a digest, returning the decoded size. Both halves are required: a plugin
// may hash a cache key, and base64 alone is ordinary.
func hostnameKeyedOption(name, value string) (int, bool) {
	if !digestOptionName.MatchString(strings.ToLower(strings.TrimSpace(name))) {
		return 0, false
	}
	decoded, ok := decodeBase64Payload(value)
	if !ok || !phpSerializedArray.Match(decoded) {
		return 0, false
	}
	return len(decoded), true
}

// decodeBase64Payload decodes a stored base64 value. Kits wrap the stored text
// at arbitrary widths, so whitespace is removed before decoding, and padding is
// not always present.
func decodeBase64Payload(value string) ([]byte, bool) {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch r {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			continue
		}
		b.WriteRune(r)
	}
	compact := b.String()
	if compact == "" {
		return nil, false
	}
	if decoded, err := base64.StdEncoding.DecodeString(compact); err == nil {
		return decoded, true
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(compact); err == nil {
		return decoded, true
	}
	return nil, false
}

// doorwaySitemapRoutes returns the cluster numbers routed from a numbered
// sitemap into the matching numbered feed.
func doorwaySitemapRoutes(rewriteRules string) []string {
	routed := make(map[string]bool)
	for _, m := range numberedSitemapRoute.FindAllStringSubmatch(rewriteRules, -1) {
		routed[strings.TrimLeft(m[1], "0")] = true
	}
	if len(routed) == 0 {
		return nil
	}
	var out []string
	seen := make(map[string]bool)
	for _, m := range numberedSitemapFeed.FindAllStringSubmatch(rewriteRules, -1) {
		number := strings.TrimLeft(m[1], "0")
		if routed[number] && !seen[number] {
			seen[number] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// checkWPCloakConfig reports doorway scaffolding kept in the options table.
func checkWPCloakConfig(user string, creds wpDBCreds, prefix string) []alert.Finding {
	query := fmt.Sprintf(
		"(SELECT 'opt' AS kind, option_name, LEFT(option_value, %d) FROM %soptions "+
			"WHERE autoload NOT IN ('no', 'off') AND CHAR_LENGTH(option_name) = 32 "+
			"AND LOWER(option_name) REGEXP '^[0-9a-f]{32}$' LIMIT %d) UNION ALL "+
			"(SELECT 'rules', option_name, LEFT(option_value, %d) FROM %soptions "+
			"WHERE option_name = 'rewrite_rules' LIMIT 1)",
		maxCloakOptionBytes, prefix, maxCloakOptionRows+1, maxCloakOptionBytes, prefix)

	var keyed []string
	var routes []string
	candidates := 0
	for _, line := range runMySQLQuery(creds, query) {
		parts := strings.SplitN(strings.TrimRight(line, "\r\n"), "\t", 3)
		if len(parts) != 3 {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		name := strings.TrimSpace(mysqlclient.BatchUnescape(parts[1]))
		value := mysqlclient.BatchUnescape(parts[2])
		switch strings.TrimSpace(parts[0]) {
		case "opt":
			if candidates++; candidates > maxCloakOptionRows {
				markCheckIncomplete(creds.queryCtx, "db_content")
				continue
			}
			if size, ok := hostnameKeyedOption(name, value); ok {
				keyed = append(keyed, fmt.Sprintf("%s (%d bytes decoded)", name, size))
			}
		case "rules":
			routes = append(routes, doorwaySitemapRoutes(value)...)
		}
	}

	var findings []alert.Finding
	if len(keyed) > 0 {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "db_hostname_keyed_option",
			Message: fmt.Sprintf("%d autoloaded WordPress options are named by digest and hold encoded data (account: %s)",
				len(keyed), user),
			Details: dbContentFindingDetails(creds.dbName, prefix,
				"An option named after a digest cannot be found without already knowing "+
					"the key, and the base64 layer keeps its contents out of any search of "+
					"the table. Cloak kits key that digest to the site's own hostname so one "+
					"payload serves many sites. The row is autoloaded, so it is read on every request.",
				cloakSample("Options", keyed)),
		})
	}
	if len(routes) > 0 {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "db_doorway_sitemap_routes",
			Message: fmt.Sprintf("%d numbered sitemap routes feed generated pages to crawlers (account: %s)",
				len(routes), user),
			Details: dbContentFindingDetails(creds.dbName, prefix,
				"Each rule routes sitemap<N>.xml straight into a matching feed, one per "+
					"doorway cluster, so crawlers are handed the generated pages without them "+
					"appearing in the site's real sitemap. Sitemap plugins add rewrite rules "+
					"too, but none of them pair a numbered sitemap with a feed of the same number.",
				cloakSample("Clusters", routes)),
		})
	}
	return findings
}

func cloakSample(label string, values []string) string {
	shown := values
	if len(shown) > maxCloakSamplesShown {
		shown = shown[:maxCloakSamplesShown]
		label += fmt.Sprintf(" (showing %d of %d)", len(shown), len(values))
	}
	return label + ": " + strings.Join(shown, ", ")
}
