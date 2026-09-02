package checks

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Cloak kits keep their configuration where nobody can find it: an option
// named after a digest of the site's own hostname, holding a base64 layer over
// a serialized array. Neither half is searchable, which is the point.

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func phpStringMap(pairs ...string) string {
	if len(pairs)%2 != 0 {
		panic("phpStringMap needs key/value pairs")
	}
	var serialized strings.Builder
	fmt.Fprintf(&serialized, "a:%d:{", len(pairs)/2)
	for _, value := range pairs {
		fmt.Fprintf(&serialized, `s:%d:"%s";`, len(value), value)
	}
	serialized.WriteByte('}')
	return serialized.String()
}

func cloakQueryRow(kind, name, value string) string {
	return cloakQueryRowWithSize(kind, name, value, len(value))
}

func cloakQueryRowWithSize(kind, name, value string, size int) string {
	return fmt.Sprintf("%s\t%s\t%d\tx%s", kind, name, size,
		hex.EncodeToString([]byte(value)))
}

func TestHostnameKeyedOption_DigestNameOverSerializedArray(t *testing.T) {
	value := b64(`a:2:{s:4:"host";s:11:"example.com";s:5:"links";a:0:{}}`)

	if _, ok := hostnameKeyedOption("f9d9cfd3e24caf45b44155cea2db0f05", value); !ok {
		t.Fatal("a digest-named option over a serialized array must be reported")
	}
}

// The digest name alone is not enough: a plugin may hash a cache key.
func TestHostnameKeyedOption_DigestNameWithOrdinaryValue(t *testing.T) {
	if _, ok := hostnameKeyedOption("f9d9cfd3e24caf45b44155cea2db0f05", "1"); ok {
		t.Fatal("a digest-named option holding an ordinary value is not a cloak config")
	}
}

// Base64 that decodes to something other than a serialized array is not it.
func TestHostnameKeyedOption_Base64OfNonSerializedData(t *testing.T) {
	if _, ok := hostnameKeyedOption("f9d9cfd3e24caf45b44155cea2db0f05", b64("just some text")); ok {
		t.Fatal("base64 of plain text is not a serialized array")
	}
}

// A readable name is findable, which is the opposite of the technique.
func TestHostnameKeyedOption_NamedOptionIgnored(t *testing.T) {
	value := b64(`a:1:{s:1:"a";s:1:"b";}`)
	for _, name := range []string{
		"my_plugin_cache",
		"f9d9cfd3e24caf45b44155cea2db0f0",   // 31 chars
		"f9d9cfd3e24caf45b44155cea2db0f055", // 33 chars
		"f9d9cfd3e24caf45b44155cea2db0g05",  // not hex
	} {
		if _, ok := hostnameKeyedOption(name, value); ok {
			t.Errorf("option %q reported as digest-named", name)
		}
	}
}

// Whitespace inside the stored base64 must not defeat the decode. Go's decoder
// already ignores CR and LF on its own, so this has to use the separators it
// does reject, or it proves nothing about the stripping.
func TestHostnameKeyedOption_ToleratesWrappedBase64(t *testing.T) {
	raw := b64(`a:1:{s:1:"a";s:1:"b";}`)

	for name, wrapped := range map[string]string{
		"space": raw[:8] + " " + raw[8:],
		"tab":   raw[:8] + "\t" + raw[8:],
	} {
		if _, ok := hostnameKeyedOption("f9d9cfd3e24caf45b44155cea2db0f05", wrapped); !ok {
			t.Errorf("base64 wrapped on a %s did not decode", name)
		}
	}
}

func TestHostnameKeyedOption_ToleratesUnpaddedBase64(t *testing.T) {
	raw := strings.TrimRight(b64(`a:1:{s:1:"a";s:1:"b";}`), "=")
	if _, ok := hostnameKeyedOption("f9d9cfd3e24caf45b44155cea2db0f05", raw); !ok {
		t.Fatal("unpadded standard base64 did not decode")
	}
}

func TestHostnameKeyedOption_RejectsInvalidEncodedInput(t *testing.T) {
	digest := "f9d9cfd3e24caf45b44155cea2db0f05"
	valid := b64(`a:1:{s:1:"a";s:1:"b";}`)
	for name, value := range map[string]string{
		"base64url alphabet": valid + "_",
		"embedded NUL":       valid[:8] + "\x00" + valid[8:],
		"trailing garbage":   valid + "!",
		"over byte limit":    strings.Repeat("!", maxCloakOptionBytes+1),
	} {
		if _, ok := hostnameKeyedOption(digest, value); ok {
			t.Errorf("%s input reported as cloak configuration", name)
		}
	}
}

func TestHostnameKeyedOption_RequiresCompletePHPSerialization(t *testing.T) {
	digest := "f9d9cfd3e24caf45b44155cea2db0f05"
	for name, decoded := range map[string]string{
		"opening marker only": `a:1:{`,
		"wrong item count":    `a:1:{}`,
		"NUL outside string":  "a:0:{\x00}",
		"trailing data":       `a:0:{}garbage`,
	} {
		if _, ok := hostnameKeyedOption(digest, b64(decoded)); ok {
			t.Errorf("%s reported as a serialized array", name)
		}
	}

	// NUL is legal inside a PHP serialized string when its byte length says
	// so; rejecting it wholesale would miss valid binary configuration data.
	validBinary := "a:1:{s:1:\"k\";s:1:\"\x00\";}"
	if _, ok := hostnameKeyedOption(digest, b64(validBinary)); !ok {
		t.Fatal("valid serialized binary string was rejected")
	}
}

func TestHostnameKeyedOption_AcceptsCommonPHPSerializedValues(t *testing.T) {
	serialized := `a:8:{i:0;N;i:1;b:1;i:2;i:-2;i:3;d:1.5;i:4;s:3:"abc";` +
		`i:5;a:0:{}i:6;O:8:"stdClass":0:{}i:7;C:1:"X":3:{abc}}`
	if _, ok := hostnameKeyedOption("f9d9cfd3e24caf45b44155cea2db0f05", b64(serialized)); !ok {
		t.Fatal("valid nested scalar and object values were rejected")
	}
}

func TestHostnameKeyedOption_DigestNameIsExactASCII(t *testing.T) {
	value := b64(`a:0:{}`)
	if _, ok := hostnameKeyedOption("F9D9CFD3E24CAF45B44155CEA2DB0F05", value); !ok {
		t.Fatal("uppercase hexadecimal digest was rejected")
	}
	for _, name := range []string{
		" f9d9cfd3e24caf45b44155cea2db0f05",
		"f9d9cfd3e24caf45b44155cea2db0f05 ",
		strings.Repeat("a", 31) + "\u00e9", // 32 characters but 33 UTF-8 bytes.
	} {
		if _, ok := hostnameKeyedOption(name, value); ok {
			t.Errorf("non-exact digest name %q was accepted", name)
		}
	}
}

// The encoding layer is half the technique: it keeps the contents out of any
// search of the table. A digest-named row holding a plainly readable
// serialized array is a hashed cache key, which plugins do write.
func TestHostnameKeyedOption_RequiresTheEncodingLayer(t *testing.T) {
	if _, ok := hostnameKeyedOption("f9d9cfd3e24caf45b44155cea2db0f05", `a:1:{s:1:"a";s:1:"b";}`); ok {
		t.Fatal("an unencoded serialized array is not the cloak shape")
	}
}

// --- doorway sitemap routes ----------------------------------------------

// One sitemap per doorway cluster, rewritten straight to a feed, so crawlers
// are handed the generated pages without them appearing in the real sitemap.
func TestDoorwaySitemapRoutes_PairedNumbers(t *testing.T) {
	rules := phpStringMap(
		`sitemap1042\.xml$`, `index.php?feed=xmlsitemap1042`,
		`sitemap1043\.xml$`, `index.php?feed=xmlsitemap1043`,
	)

	got := doorwaySitemapRoutes(rules)
	if len(got) != 2 {
		t.Fatalf("routes = %v, want both clusters", got)
	}
}

// Real sitemap plugins add rewrite rules too; they do not route a numbered
// sitemap into a matching numbered feed.
func TestDoorwaySitemapRoutes_IgnoresRealSitemapPlugins(t *testing.T) {
	// A numbered sitemap route on its own is ordinary -- plugins publish
	// paginated sitemaps. It is the matching numbered feed that is the kit.
	rules := phpStringMap(
		`sitemap_index\.xml$`, `index.php?sitemap=1`,
		`([^/]+?)-sitemap([0-9]+)?\.xml$`, `index.php?sitemap=$1&sitemap_n=$2`,
		`sitemap42\.xml$`, `index.php?sitemap=posts&sitemap_n=42`,
	)

	if got := doorwaySitemapRoutes(rules); len(got) != 0 {
		t.Fatalf("real sitemap plugin rules reported: %v", got)
	}
}

// The number must correspond: an unpaired feed is not the doorway shape.
func TestDoorwaySitemapRoutes_RequiresMatchingNumber(t *testing.T) {
	rules := phpStringMap(`sitemap1042\.xml$`, `index.php?feed=xmlsitemap7`)

	if got := doorwaySitemapRoutes(rules); len(got) != 0 {
		t.Fatalf("mismatched numbers reported: %v", got)
	}
}

func TestDoorwaySitemapRoutes_RequiresOneRulePair(t *testing.T) {
	rules := phpStringMap(
		`sitemap7\.xml$`, `index.php?sitemap=7`,
		`unrelated-route$`, `index.php?feed=xmlsitemap7`,
	)
	if got := doorwaySitemapRoutes(rules); len(got) != 0 {
		t.Fatalf("unrelated rewrite rules were correlated: %v", got)
	}
}

func TestDoorwaySitemapRoutes_RequiresExactRouteAndFeedParameter(t *testing.T) {
	for name, keyAndValue := range map[string][2]string{
		"different parameter":   {`sitemap7\.xml$`, `index.php?target=xmlsitemap7`},
		"parameter name suffix": {`sitemap7\.xml$`, `index.php?myfeed=xmlsitemap7`},
		"prefixed route":        {`post-sitemap7\.xml$`, `index.php?feed=xmlsitemap7`},
		"route path suffix":     {`sitemap7\.xml/extra$`, `index.php?feed=xmlsitemap7`},
	} {
		rules := phpStringMap(keyAndValue[0], keyAndValue[1])
		if got := doorwaySitemapRoutes(rules); len(got) != 0 {
			t.Errorf("%s was reported as an exact doorway route: %v", name, got)
		}
	}
}

func TestDoorwaySitemapRoutes_CanonicalizesAndDeduplicatesNumbers(t *testing.T) {
	rules := phpStringMap(
		`sitemap007\.xml$`, `index.php?feed=xmlsitemap7`,
		`sitemap7\.xml$`, `index.php?feed=xmlsitemap0007`,
		`sitemap000\.xml$`, `index.php?feed=xmlsitemap0`,
	)
	got := doorwaySitemapRoutes(rules)
	if len(got) != 2 || got[0] != "0" || got[1] != "7" {
		t.Fatalf("canonical routes = %v, want [0 7]", got)
	}
}

func TestDoorwaySitemapRoutes_RejectsLongNumericPrefix(t *testing.T) {
	for name, feed := range map[string]string{
		"11-digit feed":     `xmlsitemap12345678901`,
		"alphanumeric feed": `xmlsitemap1234567890evil`,
	} {
		rules := phpStringMap(
			`sitemap1234567890\.xml$`, `index.php?feed=`+feed,
		)
		if got := doorwaySitemapRoutes(rules); len(got) != 0 {
			t.Errorf("%s was matched by a numeric prefix: %v", name, got)
		}
	}
}

func TestDoorwaySitemapRoutes_RejectsTruncatedSerialization(t *testing.T) {
	rules := phpStringMap(`sitemap7\.xml$`, `index.php?feed=xmlsitemap7`)
	if got, complete := doorwaySitemapRoutesChecked(rules[:len(rules)-1]); complete || len(got) != 0 {
		t.Fatalf("truncated rewrite_rules parsed as complete: routes=%v complete=%v", got, complete)
	}
}

// --- finding construction -------------------------------------------------

func cloakFindings(t *testing.T, rows []string) []alert.Finding {
	t.Helper()
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, _ string) []string { return rows }
	t.Cleanup(func() { runMySQLQuery = prev })
	return checkWPCloakConfig("alice", wpDBCreds{dbName: "wp"}, "wp_")
}

func TestCheckWPCloakConfig_ReportsHostnameKeyedOption(t *testing.T) {
	rows := []string{
		cloakQueryRow("opt", "f9d9cfd3e24caf45b44155cea2db0f05",
			b64(`a:1:{s:4:"host";s:11:"example.com";}`)),
	}

	got := cloakFindings(t, rows)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %+v", got)
	}
	if got[0].Check != "db_hostname_keyed_option" {
		t.Errorf("check = %q", got[0].Check)
	}
	if !strings.Contains(got[0].Details, "f9d9cfd3e24caf45b44155cea2db0f05") {
		t.Errorf("details must name the option, got:\n%s", got[0].Details)
	}
}

func TestCheckWPCloakConfig_ReportsDoorwaySitemapRoutes(t *testing.T) {
	rows := []string{
		cloakQueryRow("rules", "rewrite_rules",
			phpStringMap(`sitemap1042\.xml$`, `index.php?feed=xmlsitemap1042`)),
	}

	got := cloakFindings(t, rows)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %+v", got)
	}
	if got[0].Check != "db_doorway_sitemap_routes" {
		t.Errorf("check = %q", got[0].Check)
	}
	if !strings.Contains(got[0].Details, "1042") {
		t.Errorf("details must name the cluster, got:\n%s", got[0].Details)
	}
}

// The row has to be autoloaded to serve the cloak on every request, and that
// is also what separates it from the hashed cache keys plugins leave behind.
// WordPress considers exactly yes/on/auto-on/auto autoloaded. An IN predicate
// also deliberately excludes off/no/auto-off, unknown values, and SQL NULL.
func TestCheckWPCloakConfig_QueryScopesToAutoloadedDigestNames(t *testing.T) {
	prev := runMySQLQuery
	var queries []string
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		queries = append(queries, query)
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	checkWPCloakConfig("alice", wpDBCreds{dbName: "wp"}, "wp_")

	if len(queries) != 1 {
		t.Fatalf("queries = %d, want one options read", len(queries))
	}
	for _, want := range []string{
		"autoload IN ('yes', 'on', 'auto-on', 'auto')",
		"OCTET_LENGTH(option_name) = 32",
		"UNHEX(option_name) IS NOT NULL",
		"OCTET_LENGTH(option_value)",
		"CAST(option_value AS BINARY)",
		"rewrite_rules",
	} {
		if !strings.Contains(queries[0], want) {
			t.Errorf("query missing %q: %s", want, queries[0])
		}
	}
	for _, unwanted := range []string{"autoload NOT IN", "CHAR_LENGTH(option_name)", "LOWER(option_name) REGEXP"} {
		if strings.Contains(queries[0], unwanted) {
			t.Errorf("query retains ambiguous filter %q: %s", unwanted, queries[0])
		}
	}
}

func TestCheckWPCloakConfig_SilentOnACleanSite(t *testing.T) {
	rows := []string{
		cloakQueryRow("rules", "rewrite_rules",
			phpStringMap(`sitemap_index\.xml$`, `index.php?sitemap=1`)),
	}

	if got := cloakFindings(t, rows); len(got) != 0 {
		t.Fatalf("clean site reported: %+v", got)
	}
}

func TestCheckWPCloakConfig_TruncatedRewriteRulesMarkIncomplete(t *testing.T) {
	rule := phpStringMap(`sitemap7\.xml$`, `index.php?feed=xmlsitemap7`)
	truncated := rule + strings.Repeat("x", maxCloakOptionBytes-len(rule))
	rows := []string{
		cloakQueryRowWithSize("rules", "rewrite_rules", truncated, maxCloakOptionBytes+1),
	}
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, _ string) []string { return rows }
	t.Cleanup(func() { runMySQLQuery = prev })
	ctx, incomplete := withIncompleteCheckCollector(t.Context())

	got := checkWPCloakConfig("alice", wpDBCreds{dbName: "wp", queryCtx: ctx}, "wp_")
	if len(got) != 0 {
		t.Fatalf("truncated rewrite_rules fabricated a finding: %+v", got)
	}
	if !incomplete.contains("db_content") {
		t.Fatal("truncated rewrite_rules did not mark the database scan incomplete")
	}
}

func TestCheckWPCloakConfig_MalformedTransportMarksIncomplete(t *testing.T) {
	rows := []string{"rules\trewrite_rules\t4\txZZZZ"}
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, _ string) []string { return rows }
	t.Cleanup(func() { runMySQLQuery = prev })
	ctx, incomplete := withIncompleteCheckCollector(t.Context())

	if got := checkWPCloakConfig("alice", wpDBCreds{dbName: "wp", queryCtx: ctx}, "wp_"); len(got) != 0 {
		t.Fatalf("malformed rows fabricated findings: %+v", got)
	}
	if !incomplete.contains("db_content") {
		t.Fatal("malformed cloak rows did not mark the database scan incomplete")
	}
}

func TestCheckWPCloakConfig_NonArrayRulesStayComplete(t *testing.T) {
	for name, value := range map[string]string{
		"empty":             "",
		"malformed array":   `a:1:{s:3:"bad";}`,
		"serialized scalar": `b:0;`,
	} {
		t.Run(name, func(t *testing.T) {
			prev := runMySQLQuery
			runMySQLQuery = func(_ wpDBCreds, _ string) []string {
				return []string{cloakQueryRow("rules", "rewrite_rules", value)}
			}
			t.Cleanup(func() { runMySQLQuery = prev })
			ctx, incomplete := withIncompleteCheckCollector(t.Context())

			if got := checkWPCloakConfig("alice", wpDBCreds{dbName: "wp", queryCtx: ctx}, "wp_"); len(got) != 0 {
				t.Fatalf("non-array rules fabricated findings: %+v", got)
			}
			if incomplete.contains("db_content") {
				t.Fatal("a fully read non-array option marked the database scan incomplete")
			}
		})
	}
}

func TestCheckWPCloakConfig_DuplicateClusterCountsOnce(t *testing.T) {
	rules := phpStringMap(
		`sitemap007\.xml$`, `index.php?feed=xmlsitemap7`,
		`sitemap7\.xml$`, `index.php?feed=xmlsitemap0007`,
	)
	got := cloakFindings(t, []string{cloakQueryRow("rules", "rewrite_rules", rules)})
	if len(got) != 1 || !strings.HasPrefix(got[0].Message, "1 numbered sitemap route feeds") {
		t.Fatalf("duplicate cluster count = %+v", got)
	}
}

func TestCheckWPCloakConfig_DigestCandidateLimitIsALowerBound(t *testing.T) {
	value := b64(`a:0:{}`)
	rows := make([]string, 0, maxCloakOptionRows+1)
	for i := 1; i <= maxCloakOptionRows+1; i++ {
		rows = append(rows, cloakQueryRow("opt", fmt.Sprintf("%032x", i), value))
	}
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, _ string) []string { return rows }
	t.Cleanup(func() { runMySQLQuery = prev })
	ctx, incomplete := withIncompleteCheckCollector(t.Context())

	got := checkWPCloakConfig("alice", wpDBCreds{dbName: "wp", queryCtx: ctx}, "wp_")
	if len(got) != 1 || !strings.HasPrefix(got[0].Message, "at least 50 autoloaded WordPress options are") {
		t.Fatalf("bounded candidate finding = %+v", got)
	}
	if !incomplete.contains("db_content") {
		t.Fatal("digest candidate look-ahead row did not mark the scan incomplete")
	}
}
