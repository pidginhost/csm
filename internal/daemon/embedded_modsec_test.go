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
	// The User-Agent rule and the batch rate limit were both bypassed in the
	// 2026-08-01 wave (spoofed browser UAs, requests paced under the window).
	// This parameter was on every request of both waves.
	for _, tc := range []struct {
		uri   string
		match bool
	}{
		{"/?rest_route=/batch/v1&_w2s=bf49e2b6", true},
		{"/wp-login.php?_w2s=f91570af", true},
		{"/?a=1&_w2s=0673563c", true},
		{"/?_W2S=bf49e2b6", true},
		{"/?%5fw%32s=bf49e2b6", true},
		{"/?%255fw2s=bf49e2b6", true},
		{"/?_w2s=first&_w2s=second", true},
		{"/?rest_route=/batch/v1", false},
		{"/normal/page/", false},
		{"/?myw2s=1", false},
		{"/?_w2s_token=1", false},
		{"/?next=%2Ftarget%3F_w2s%3Dbf49e2b6", false},
		{"/?payload=prefix_w2s%3Dbf49e2b6", false},
	} {
		if got := queryHasModSecArgName(t, tc.uri, "_w2s"); got != tc.match {
			t.Errorf("fingerprint match for %q = %v, want %v", tc.uri, got, tc.match)
		}
	}
}

func queryHasModSecArgName(t *testing.T, uri, want string) bool {
	t.Helper()
	parsed, err := url.ParseRequestURI(uri)
	if err != nil {
		t.Fatalf("parse request URI %q: %v", uri, err)
	}
	for _, field := range strings.Split(parsed.RawQuery, "&") {
		name, _, _ := strings.Cut(field, "=")
		// ARGS_GET_NAMES provides the parser-decoded name. The rule's
		// urlDecodeUni transformation normalizes one remaining encoded layer.
		for range 2 {
			name, err = url.QueryUnescape(name)
			if err != nil {
				return false
			}
		}
		if strings.EqualFold(name, want) {
			return true
		}
	}
	return false
}
