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

// CVE-2024-28000: LiteSpeed Cache below 6.4 signs the crawler's role
// simulation with a six-character hash (Str::rrand(6), one million values
// seeded from microsecond timing), so an unauthenticated attacker can brute
// force it and have WordPress treat the request as that user. Sites whose
// WordPress is too old for the fixed plugin line have no upgrade path, which
// is what this patch is for.
func TestModSecBlocksLiteSpeedRoleSimulation(t *testing.T) {
	conf := string(embeddedModSec)
	if !strings.Contains(conf, "id:900128") {
		t.Fatal("id:900128 missing: no virtual patch for CVE-2024-28000")
	}
	if !strings.Contains(conf, "CVE-2024-28000") {
		t.Fatal("rules do not name CVE-2024-28000")
	}
	// The patch must stand on request shape alone. SERVER_ADDR and other
	// engine-specific variables cannot be verified against LiteSpeed's
	// ModSecurity from here, and an unknown variable aborts the whole
	// configuration load, taking every other rule down with it.
	start := strings.Index(conf, "CVE-2024-28000")
	if start < 0 {
		t.Fatal("CVE-2024-28000 patch block not found")
	}
	patch := conf[start:]
	for _, fragile := range []string{"SERVER_ADDR", "REMOTE_ADDR"} {
		if strings.Contains(patch, fragile) {
			t.Errorf("the CVE-2024-28000 patch depends on %s; keep it to request shape", fragile)
		}
	}
}

// Check complete chains rather than finding a matching regex somewhere later
// in the file. A missing link must fail even if the next rule contains it.
func liteSpeedSimulationChains(t *testing.T) [][]string {
	t.Helper()
	conf := string(embeddedModSec)
	start := strings.Index(conf, "# --- CVE-2024-28000:")
	if start < 0 {
		t.Fatal("LiteSpeed simulation rules missing")
	}
	conf = strings.ReplaceAll(conf[start:], "\\\n", "")
	links := regexp.MustCompile(`(?m)^SecRule (?:"([^"]+)"|(\S+)) "([^"]+)"\s+"([^"]+)"`).FindAllStringSubmatch(conf, -1)
	if len(links) != 6 {
		t.Fatalf("got %d chain links, want two complete three-link rules", len(links))
	}
	for i, link := range links {
		if link[1] == "" {
			link[1] = link[2]
		}
		actions := strings.Split(strings.ReplaceAll(link[4], " ", ""), ",")
		if i%3 != 2 && actions[len(actions)-1] != "chain" {
			t.Errorf("link %d: chain must be the last action", i)
		}
		if i%3 == 0 {
			for _, required := range []string{"id:" + strconv.Itoa(900128+i/3), "phase:1", "deny", "status:403", "log", "t:none"} {
				if !strings.Contains(link[4], required) {
					t.Errorf("chain starter %d missing %s", i, required)
				}
			}
		} else {
			for _, action := range actions {
				if !strings.HasPrefix(action, "t:") && (action != "chain" || i%3 != 1) {
					t.Errorf("link %d has a starter-only or unexpected action %q", i, action)
				}
			}
		}
	}
	return links
}

func TestLiteSpeedSimulationChainSyntax(t *testing.T) {
	liteSpeedSimulationChains(t)
}

func TestLiteSpeedSimulationCookieSemantics(t *testing.T) {
	links := liteSpeedSimulationChains(t)
	for _, offset := range []int{0, 3} {
		role, hash := links[offset], links[offset+1]
		for _, tc := range []struct {
			link []string
			name string
			want string
		}{
			{role, "role", `REQUEST_COOKIES:/^litespeed[._\x20\[]role$/`},
			{hash, "hash", `REQUEST_COOKIES:/^litespeed[._\x20\[]hash$/`},
		} {
			if tc.link[1] != tc.want {
				t.Errorf("%s selector = %q, must cover PHP cookie name aliases", tc.name, tc.link[1])
			}
		}
		roleRE := regexp.MustCompile(strings.TrimPrefix(role[3], "@rx "))
		for _, value := range []string{"1", "+1", "1.0", "1e0", "%31", " 1"} {
			if !roleRE.MatchString(value) {
				t.Errorf("role gate misses PHP numeric ID %q", value)
			}
		}
		if !strings.Contains(hash[4], "t:none,t:urlDecode") {
			t.Error("hash must decode PHP cookie values")
		}
		hashRE := regexp.MustCompile(strings.TrimPrefix(hash[3], "@rx "))
		for _, tc := range []struct {
			value string
			match bool
		}{
			{"Ab3Xz9", true}, {"%41b3Xz9", true},
			{"a", true}, {strings.Repeat("a", 16), true},
			{strings.Repeat("a", 17), false}, {strings.Repeat("a", 32), false},
			{"+123456", true}, {"123456.0", true}, {"1.23456e5", true}, {"1.23456e+5", true},
			{"00000000000000000000000000123456", true},
			{"", false}, {"a1b2-c3", false},
		} {
			value, err := url.QueryUnescape(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if got := hashRE.MatchString(value); got != tc.match {
				t.Errorf("hash %q matched = %v, want %v", tc.value, got, tc.match)
			}
		}
	}
}

func TestLiteSpeedSimulationRequestSemantics(t *testing.T) {
	links := liteSpeedSimulationChains(t)
	scope := links[2]
	if scope[1] != `REQUEST_FILENAME|ARGS_GET:/^\x20*rest[._\x20\[]route$/` {
		t.Fatalf("scope must separate paths from PHP-normalized REST query fields, got %q", scope[1])
	}
	scopeRE := regexp.MustCompile(strings.TrimPrefix(scope[3], "@rx "))
	for _, tc := range []struct {
		value string
		match bool
	}{
		{"/wp-admin", true}, {"/blog/wp-admin/users.php", true},
		{"/wp-json/wp/v2/users", true}, {"/wp/v2/users", true}, {"wp/v2/users", true},
		{"/shop/product/", false}, {"/wp-json/wp/v2/posts", false},
		{"/wp-json/wp/v2/users-guide", false}, {"/wp-admin-guide/", false},
	} {
		if got := scopeRE.MatchString(tc.value); got != tc.match {
			t.Errorf("scope %q matched = %v, want %v", tc.value, got, tc.match)
		}
	}
	method := links[5]
	if method[1] != `REQUEST_METHOD|REQUEST_HEADERS:/(?i)^x[._-]http[._-]method[._-]override$/|ARGS_GET:/^\x20*[._\[]method$/` {
		t.Fatalf("write guard must inspect PHP method overrides, got %q", method[1])
	}
	if !strings.HasPrefix(method[3], "!@rx ") {
		t.Fatal("method guard must be a negated read match")
	}
	methodRE := regexp.MustCompile(strings.TrimPrefix(method[3], "!@rx "))
	for _, value := range []string{"POST", "PUT", "PATCH", "DELETE", "post"} {
		if methodRE.MatchString(value) {
			t.Errorf("write %q exempted as a crawler read", value)
		}
	}
	for _, value := range []string{"GET", "HEAD", "get", "head"} {
		if !methodRE.MatchString(value) {
			t.Errorf("read override %q blocked", value)
		}
	}
}

// Keep one deny ID: operators disable it and its hit history is HTTP-only.
// Helper rules must only mark this transaction, never bypass other protections.
func userEnumerationRules(t *testing.T) [][]string {
	t.Helper()
	conf := string(embeddedModSec)
	const marker = "# --- Generic: Block REST API user enumeration"
	start := strings.Index(conf, marker)
	if start < 0 {
		t.Fatal("user enumeration rule block missing")
	}
	block := conf[start:]
	if next := strings.Index(block[len(marker):], "\n# --- "); next >= 0 {
		block = block[:len(marker)+next]
	}
	block = strings.ReplaceAll(block, "\\\n", "")
	rules := regexp.MustCompile(`(?m)^SecRule (?:"([^"]+)"|(\S+)) "([^"]+)"(?:\s+"([^"]+)")?`).FindAllStringSubmatch(block, -1)
	if len(rules) != 5 {
		t.Fatalf("got %d user enumeration rules, want three helpers and a two-link deny", len(rules))
	}
	for _, rule := range rules {
		if rule[1] == "" {
			rule[1] = rule[2]
		}
	}
	return rules
}

func TestModSecUserEnumerationChainSyntax(t *testing.T) {
	rules := userEnumerationRules(t)
	for i, rule := range rules {
		actions := strings.Split(strings.ReplaceAll(rule[4], " ", ""), ",")
		want := []string{"t:none"}
		switch i {
		case 0, 1, 2:
			want = append(want, "id:"+strconv.Itoa(900130+i), "phase:1", "pass", "nolog")
			value := "1"
			if i == 2 {
				value = "0"
			}
			want = append(want, "setvar:tx.csm_wp_user_route="+value)
			if i == 0 {
				want = append(want, "t:urlDecode", "t:normalizePath")
			}
		case 3:
			want = append(want, "id:900112", "phase:1", "deny", "status:403", "log",
				"msg:'CSMVP:WordPressuserenumerationblocked'", "chain")
		}
		if len(actions) != len(want) {
			t.Errorf("rule %d: actions %v, want only %v", i, actions, want)
		}
		for _, required := range want {
			found := false
			for _, action := range actions {
				if action == required {
					found = true
				}
			}
			if !found {
				t.Errorf("rule %d missing %s", i, required)
			}
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(rules[3][4]), "chain") {
		t.Error("deny starter must continue to the Authorization guard")
	}
	if !strings.Contains(rules[3][4], "msg:'CSM VP: WordPress user enumeration blocked'") {
		t.Error("rule message changed; the web UI and hit history describe the rule by it")
	}
}

func TestModSecUserEnumerationRouteSemantics(t *testing.T) {
	rules := userEnumerationRules(t)
	if rules[0][1] != "REQUEST_FILENAME" {
		t.Fatal("path matcher must inspect only the path")
	}
	const selector = `ARGS_GET:/^\x20*rest[._\x20\[]route$/`
	if rules[1][1] != selector {
		t.Fatalf("query selector = %q, want PHP-normalized rest_route names", rules[1][1])
	}
	for _, tc := range []struct {
		value string
		path  bool
		query bool
	}{
		{"/wp-json/wp/v2/users", true, false},
		{"/wp-json/wp/v2/users/", true, false},
		{"/wp-json/wp/v2/users/1", true, false},
		{"/wp-json/wp/v2/users/me/application-passwords", true, false},
		{"/blog/wp-json/wp/v2/users", true, false},
		{"/index.php/wp-json/wp/v2/users", true, false},
		{"/WP-JSON/WP/V2/USERS", true, false},
		{"/wp-json/wp/v2/users\\", true, false},
		{"/wp/v2/users", false, true},
		{"wp/v2/users", false, true},
		{"/WP/V2/USERS", false, true},
		{"wp/v2/users/2", false, true},
		{"/wp/v2/users\\\\/", false, true},
		{"/wp/v2/users\\guide", false, false},
		{"/wp-json/wp/v2/users-guide", false, false},
		{"/wp-json/wp/v2/usersx", false, false},
		{"/wp-json/wp/v2/posts", false, false},
		{"/docs/wp/v2/users", false, false},
		{"/custom/../wp/v2/users", false, false},
		{"%2Fwp%2Fv2%2Fusers", false, false},
		{"/wp/v2/users%2Fguide", false, false},
		{"/mywp/v2/users", false, false},
		{"/shop/", false, false},
	} {
		for i, want := range []bool{tc.path, tc.query} {
			routeRE := regexp.MustCompile(strings.TrimPrefix(rules[i][3], "@rx "))
			if got := routeRE.MatchString(tc.value); got != want {
				t.Errorf("matcher %d route %q matched = %v, want %v", i, tc.value, got, want)
			}
		}
	}
}

func TestModSecUserEnumerationExemptsAuthenticatedRequests(t *testing.T) {
	rules := userEnumerationRules(t)
	if rules[2][1] != `REQUEST_COOKIES:/^wordpress_logged_in_/` || rules[2][3] != "@rx ^" {
		t.Error("session helper must positively match cookie presence, including empty values")
	}
	if rules[3][1] != "TX:csm_wp_user_route" || rules[3][3] != "@eq 1" {
		t.Error("deny must read the route flag after the session helper clears it")
	}
	if rules[4][1] != "&REQUEST_HEADERS:Authorization" || rules[4][3] != "@eq 0" {
		t.Error("final deny link must require a missing Authorization header")
	}
}
