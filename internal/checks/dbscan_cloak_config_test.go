package checks

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Cloak kits keep their configuration where nobody can find it: an option
// named after a digest of the site's own hostname, holding a base64 layer over
// a serialized array. Neither half is searchable, which is the point.

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

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
	rules := `a:2:{s:18:"sitemap1042\.xml$";s:36:"index.php?feed=xmlsitemap1042";` +
		`s:18:"sitemap1043\.xml$";s:36:"index.php?feed=xmlsitemap1043";}`

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
	rules := `a:3:{s:19:"sitemap_index\.xml$";s:19:"index.php?sitemap=1";` +
		`s:31:"([^/]+?)-sitemap([0-9]+)?\.xml$";s:44:"index.php?sitemap=$1&sitemap_n=$2";` +
		`s:16:"sitemap42\.xml$";s:38:"index.php?sitemap=posts&sitemap_n=42";}`

	if got := doorwaySitemapRoutes(rules); len(got) != 0 {
		t.Fatalf("real sitemap plugin rules reported: %v", got)
	}
}

// The number must correspond: an unpaired feed is not the doorway shape.
func TestDoorwaySitemapRoutes_RequiresMatchingNumber(t *testing.T) {
	rules := `s:18:"sitemap1042\.xml$";s:36:"index.php?feed=xmlsitemap7";`

	if got := doorwaySitemapRoutes(rules); len(got) != 0 {
		t.Fatalf("mismatched numbers reported: %v", got)
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
		"opt\tf9d9cfd3e24caf45b44155cea2db0f05\t" + b64(`a:1:{s:4:"host";s:11:"example.com";}`),
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
		"rules\trewrite_rules\t" + `s:18:"sitemap1042\.xml$";s:36:"index.php?feed=xmlsitemap1042";`,
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
// WordPress 6.6 added 'on'/'off'/'auto' alongside the legacy 'yes'/'no', so the
// filter excludes the off values rather than naming the on ones.
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
	for _, want := range []string{"autoload NOT IN ('no', 'off')", "CHAR_LENGTH(option_name) = 32", "rewrite_rules"} {
		if !strings.Contains(queries[0], want) {
			t.Errorf("query missing %q: %s", want, queries[0])
		}
	}
}

func TestCheckWPCloakConfig_SilentOnACleanSite(t *testing.T) {
	rows := []string{
		"rules\trewrite_rules\t" + `s:19:"sitemap_index\.xml$";s:19:"index.php?sitemap=1";`,
	}

	if got := cloakFindings(t, rows); len(got) != 0 {
		t.Fatalf("clean site reported: %+v", got)
	}
}
