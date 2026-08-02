package daemon

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The wp2shell mass-exploit campaign (2026-07-23) identified itself by a
// literal User-Agent and drove privilege escalation through the WordPress
// REST batch endpoint. Both signals must be covered by the shipped ruleset.
func TestEmbeddedModSecBlocksWP2ShellUserAgent(t *testing.T) {
	conf := string(embeddedModSec)
	if !strings.Contains(conf, `SecRule REQUEST_HEADERS:User-Agent "@contains wp2shell"`) {
		t.Error("modsec ruleset does not block the wp2shell User-Agent")
	}
	if !strings.Contains(conf, "id:900122,phase:1,deny,status:403,log,t:none,t:lowercase") {
		t.Error("wp2shell User-Agent rule is case-sensitive")
	}
}

func TestEmbeddedModSecRateLimitsRESTBatchEndpoint(t *testing.T) {
	conf := string(embeddedModSec)
	const marker = "# --- Rate-limit WordPress REST batch endpoint"
	batchStart := strings.Index(conf, marker)
	if batchStart < 0 {
		t.Fatal("REST batch rate-limit block missing")
	}
	// Bound the slice to this block. Counting to end-of-file made every
	// assertion below depend on nothing else ever being appended to the
	// ruleset, so an unrelated rule broke tests that claim to measure "batch"
	// elements.
	batchBlock := conf[batchStart:]
	if next := strings.Index(batchBlock[len(marker):], "\n# --- "); next >= 0 {
		batchBlock = batchBlock[:len(marker)+next]
	}
	if got := strings.Count(batchBlock, `SecRule REQUEST_METHOD "@streq POST"`); got != 2 {
		t.Errorf("found %d batch POST guards, want 2", got)
	}
	if got := strings.Count(batchBlock, "t:none,t:urlDecodeUni"); got != 2 {
		t.Errorf("found %d batch URI normalizers, want 2", got)
	}
	const incrementGuard = "SecRule REQUEST_METHOD \"@streq POST\" \\\n" +
		"    \"setvar:ip.batch_count=+1,expirevar:ip.batch_count=60\""
	if !strings.Contains(batchBlock, incrementGuard) {
		t.Error("batch counter update is not guarded by the final POST chain rule")
	}
	const limitGuard = "SecRule IP:BATCH_COUNT \"@gt 20\" \\\n" +
		"    \"id:900124,phase:1,deny,status:429,log,msg:'CSM: REST batch endpoint rate limit',\\\n" +
		"    chain\""
	if !strings.Contains(batchBlock, limitGuard) {
		t.Error("batch deny rule does not enforce the expected counter threshold and action")
	}
	if got := strings.Count(batchBlock, "id:900123"); got != 1 {
		t.Errorf("found %d batch counter rule IDs, want 1", got)
	}
	if got := strings.Count(batchBlock, "id:900124"); got != 1 {
		t.Errorf("found %d batch deny rule IDs, want 1", got)
	}
	patterns := regexp.MustCompile(`SecRule REQUEST_URI "@rx ([^"]+)"`).FindAllStringSubmatch(batchBlock, -1)
	if len(patterns) != 2 {
		t.Fatalf("found %d batch route rules, want 2", len(patterns))
	}
	for _, match := range patterns {
		routeRE, err := regexp.Compile(match[1])
		if err != nil {
			t.Fatalf("compile batch route regex %q: %v", match[1], err)
		}
		for _, tc := range []struct {
			uri   string
			match bool
		}{
			{uri: "/wp-json/batch/v1", match: true},
			{uri: "/wp-json/batch/v1/", match: true},
			{uri: "/?rest_route=/batch/v1", match: true},
			{uri: "/?rest_route=batch/v1&context=edit", match: true},
			{uri: "/?rest_route=%2Fbatch%2Fv1", match: true},
			{uri: "/wp-json/batch/v10", match: false},
			{uri: "/?rest_route=/batch/v10", match: false},
			{uri: "/?next=/batch/v1", match: false},
		} {
			decoded, err := url.QueryUnescape(tc.uri)
			if err != nil {
				t.Fatal(err)
			}
			if got := routeRE.MatchString(decoded); got != tc.match {
				t.Errorf("batch route regex match for %q = %v, want %v", tc.uri, got, tc.match)
			}
		}
	}
}

func TestModSecWP2ShellRulesMatchInstallerCopy(t *testing.T) {
	installerPath := filepath.Join("..", "..", "configs", "csm_modsec_custom.conf")
	installer, err := os.ReadFile(installerPath)
	if err != nil {
		t.Fatal(err)
	}
	const marker = "# --- Block wp2shell mass-exploit tool User-Agent"
	embeddedStart := strings.Index(string(embeddedModSec), marker)
	installerStart := strings.Index(string(installer), marker)
	if embeddedStart < 0 || installerStart < 0 {
		t.Fatal("wp2shell rule block missing from a ModSecurity config copy")
	}
	embeddedRules := strings.TrimSpace(string(embeddedModSec)[embeddedStart:])
	installerRules := strings.TrimSpace(string(installer)[installerStart:])
	if embeddedRules != installerRules {
		t.Errorf("wp2shell ModSecurity rules differ between embedded and installer copies")
	}
}

func TestModSecEmbeddedAndInstallerCopiesAreIdentical(t *testing.T) {
	installerPath := filepath.Join("..", "..", "configs", "csm_modsec_custom.conf")
	installer, err := os.ReadFile(installerPath)
	if err != nil {
		t.Fatal(err)
	}
	// The daemon serves the embedded copy while checks/waf.go deploys the
	// packaged one from /opt/csm/configs, so a host gets whichever path ran.
	// Any drift means two servers on the same version enforce different rules;
	// comparing only the wp2shell block let an xmlrpc window and two wp-coder
	// rules diverge unnoticed.
	if string(embeddedModSec) != string(installer) {
		t.Errorf("embedded and installer ModSecurity configs differ; they must stay byte-identical")
	}
}

func TestModSecSyncedCopyPreservesEmbeddedProtections(t *testing.T) {
	conf := string(embeddedModSec)
	for _, want := range []string{
		"SecRule REQUEST_URI \"/xmlrpc\\.php$\" \\\n" +
			"    \"id:900006,phase:1,pass,nolog,\\\n" +
			"    setvar:ip.xmlrpc_count=+1,\\\n" +
			"    expirevar:ip.xmlrpc_count=600\"",
		"SecRule IP:XMLRPC_COUNT \"@gt 10\" \\\n" +
			"    \"id:900007,phase:1,deny,status:429,log,msg:'CSM: XML-RPC rate limit exceeded',\\\n" +
			"    chain\"",
		`id:900120,phase:1,deny,status:403,log,msg:'CSM: Blocked wp-coder preview endpoint'`,
		`id:900121,phase:1,deny,status:403,log,msg:'CSM: Blocked wp-coder attributes endpoint'`,
	} {
		if got := strings.Count(conf, want); got != 1 {
			t.Errorf("found %d copies of synced protection %q, want 1", got, want)
		}
	}
}

func TestEmbeddedModSecRuleIDsAreUniqueAndAvoidOperatorRange(t *testing.T) {
	ids := regexp.MustCompile(`\bid:([0-9]+)\b`).FindAllStringSubmatch(string(embeddedModSec), -1)
	if len(ids) == 0 {
		t.Fatal("no ModSecurity rule IDs found")
	}
	seen := make(map[int]bool, len(ids))
	for _, match := range ids {
		id, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatalf("parse rule ID %q: %v", match[1], err)
		}
		if seen[id] {
			t.Errorf("ModSecurity rule ID %d is duplicated", id)
		}
		seen[id] = true
		if id >= 900200 && id <= 900205 {
			t.Errorf("ModSecurity rule ID %d collides with the operator-managed range", id)
		}
	}
}

func TestModSecBlocksWP2ShellFingerprintParameter(t *testing.T) {
	conf := string(embeddedModSec)
	const rule = "SecRule ARGS_GET_NAMES \"@streq _w2s\" \\\n" +
		"    \"id:900125,phase:1,deny,status:403,log,t:none,t:urlDecodeUni,t:lowercase,msg:'CSM: Blocked wp2shell tool fingerprint'\""
	if got := strings.Count(conf, rule); got != 1 {
		t.Fatalf("found %d normalized wp2shell fingerprint rules, want 1", got)
	}
}

// The parsed-name rule alone let a percent-encoded parameter through: on
// LiteSpeed t:urlDecodeUni did not decode %5F before matching, verified against
// a live server. The raw-query rule covers that without matching the same text
// inside a parameter value.
func TestModSecBlocksEncodedWP2ShellFingerprint(t *testing.T) {
	conf := string(embeddedModSec)
	const pattern = `(?i)(?:^|&)(?:[+ ]|%(?:25)*20)*(?:_|[.]|%(?:25)*(?:5f|2e))(?:w|%(?:25)*77)(?:2|%(?:25)*32)(?:s|%(?:25)*73)=`
	const rule = `SecRule QUERY_STRING "@rx ` + pattern + `" \` + "\n" +
		`    "id:900126,phase:1,deny,status:403,log,t:none,msg:'CSM: Blocked wp2shell tool fingerprint (encoded)'"`
	if got := strings.Count(conf, rule); got != 1 {
		t.Fatalf("found %d encoded wp2shell fingerprint rules, want 1", got)
	}
	queryRE := regexp.MustCompile(pattern)
	for _, tc := range []struct {
		query string
		match bool
	}{
		{"%5Fw2s=abc", true},
		{"%5fw2s=abc", true},
		{"%255Fw2s=abc", true},
		{"%25255Fw2s=abc", true},
		{"%5fw%32s=abc", true},
		{"%255f%2577%2532%2573=abc", true},
		{"+_w2s=abc", true},
		{"++%5Fw2s=abc", true},
		{"%20_w2s=abc", true},
		{"%2520%255Fw2s=abc", true},
		{".w2s=abc", true},
		{"%2ew2s=abc", true},
		{"_w2s=abc", true},
		{"a=1&_w2s=abc", true},
		{"_W2S=abc", true},
		// The same text inside a value is not a parameter of that name.
		{"q=_w2s=x", false},
		{"q=?_w2s=x", false},
		{"q=?%5Fw2s=x", false},
		{"q=?+_w2s=x", false},
		{"q=+w2s=x", false},
		{"q=%3F_w2s%3Dx", false},
		{"q=%26%5Fw2s%3Dx", false},
		{"myw2s=1", false},
		{"+w2s=1", false},
		{"_w2s_token=1", false},
	} {
		if got := queryRE.MatchString(tc.query); got != tc.match {
			t.Errorf("encoded fingerprint match for %q = %v, want %v", tc.query, got, tc.match)
		}
	}
}

// CVE-2023-3460 is on CISA's known-exploited list and CSM shipped virtual
// patches for other Ultimate Member CVEs but not this one, so the only
// protection was a hand-added rule on a single host.
func TestModSecBlocksUltimateMemberPrivEsc(t *testing.T) {
	conf := string(embeddedModSec)
	if !strings.Contains(conf, "id:900127") {
		t.Fatal("CVE-2023-3460 virtual patch missing")
	}
	if !strings.Contains(conf, "CVE-2023-3460") {
		t.Error("rule does not name the CVE it patches")
	}
	re := regexp.MustCompile(`SecRule ARGS_NAMES "@rx (\(\?i\)[^"]+)"[\s\S]{0,240}id:900127`)
	m := re.FindStringSubmatch(conf)
	if m == nil {
		t.Fatal("CVE-2023-3460 rule does not match on ARGS_NAMES")
	}
	argRE, err := regexp.Compile(m[1])
	if err != nil {
		t.Fatalf("compile priv-esc regex: %v", err)
	}
	for _, tc := range []struct {
		arg   string
		match bool
	}{
		{"wp_capabilities", true},
		{"wp_capabilities[administrator]", true},
		{"wp.capabilities", true},
		{"wp capabilities", true},
		{"um_role", true},
		{"um.role", true},
		{"um role", true},
		{"UM_ROLE", true},
		// must not fire on ordinary registration fields
		{"user_login", false},
		{"user_email", false},
		{"role_description", false},
		{"my_um_roles_note", false},
		{"wp_capabilities_description", false},
		{"wp_capabilities-help", false},
		{"w.p_capabilities", false},
		{"w p_capabilities", false},
		{"wp_capabilit.ies", false},
		{"u.m_role", false},
		// PHP folds only dot, space and plus in parameter names. A name carrying
		// any other injected byte reaches the application as a different key, so
		// it cannot set wp_capabilities and is deliberately not matched.
		{"wp_capabiliti\\es", false},
		{"w/P_capabilities", false},
		{"u/m_role-29", false},
	} {
		if got := argRE.MatchString(tc.arg); got != tc.match {
			t.Errorf("priv-esc match for arg %q = %v, want %v", tc.arg, got, tc.match)
		}
	}
	for _, encoded := range []struct {
		arg     string
		decodes int
	}{
		{"WP%5fCAPABILITIES", 1},
		{"wp%255fcapabilities%255badministrator%255d", 2},
		{"um%2erole", 1},
		{"um+role", 1},
	} {
		arg := encoded.arg
		for i := 0; i < encoded.decodes; i++ {
			decoded, decodeErr := url.QueryUnescape(arg)
			if decodeErr != nil {
				t.Fatalf("decode argument name %q: %v", encoded.arg, decodeErr)
			}
			arg = decoded
		}
		if !argRE.MatchString(arg) {
			t.Errorf("priv-esc rule misses encoded argument %q after transforms (%q)", encoded.arg, arg)
		}
	}
	if !strings.Contains(conf, "id:900127,phase:2,deny,status:403,log,t:none,t:urlDecodeUni") {
		t.Error("priv-esc rule does not URL-decode argument names before matching")
	}
	// wp-admin must be exempt so operators can still assign roles, but a
	// registration request cannot earn that exemption by putting the path in a
	// query value.
	// REQUEST_FILENAME is the path without the query string. Matching on
	// REQUEST_URI let /?x=/wp-admin/ exempt an attacker from this patch.
	exemptionRule := regexp.MustCompile(`SecRule REQUEST_FILENAME "!@rx (\(\?i\)[^"]+)" "t:none,t:urlDecodeUni"`)
	exemptionMatch := exemptionRule.FindStringSubmatch(conf)
	if exemptionMatch == nil {
		t.Fatal("wp-admin exemption missing; role management would break")
	}
	wpAdminRE, err := regexp.Compile(exemptionMatch[1])
	if err != nil {
		t.Fatalf("compile wp-admin exemption: %v", err)
	}
	// These are REQUEST_FILENAME values: the path only, never the query. A
	// WordPress install in a subdirectory must still reach its own admin.
	for _, path := range []string{
		"/wp-admin/",
		"/wp-admin/user-edit.php",
		"/wordpress/wp-admin/users.php",
		"/site/blog/wp-admin/options.php",
	} {
		if !wpAdminRE.MatchString(path) {
			t.Errorf("wp-admin exemption misses admin path %q", path)
		}
	}
	for _, path := range []string{
		"/register/",
		"/wp-administer/register/",
		"/my-wp-admin-guide/",
		"/downloads/wp-admin.zip",
	} {
		if wpAdminRE.MatchString(path) {
			t.Errorf("wp-admin exemption wrongly covers non-admin path %q", path)
		}
	}
	// The query string is where an attacker could plant "/wp-admin/". Matching
	// REQUEST_FILENAME instead of REQUEST_URI is what makes that impossible, so
	// pin the variable rather than only the pattern.
	if !strings.Contains(conf, `SecRule REQUEST_FILENAME "!@rx`) {
		t.Error("exemption must read REQUEST_FILENAME; REQUEST_URI carries the query string")
	}
	if strings.Contains(conf, `id:900127`) && strings.Contains(conf, `SecRule REQUEST_URI "!@rx (?i)(?:^|/)wp-admin`) {
		t.Error("exemption still reads REQUEST_URI, which a query value can satisfy")
	}
}
