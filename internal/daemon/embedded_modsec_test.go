package daemon

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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
	for _, want := range []string{"ip.batch_count", "@gt 20", "expirevar:ip.batch_count=60", "t:none,t:urlDecodeUni"} {
		if !strings.Contains(conf, want) {
			t.Errorf("modsec ruleset missing REST batch rate-limit element %q", want)
		}
	}

	const marker = "# --- Rate-limit WordPress REST batch endpoint"
	batchStart := strings.Index(conf, marker)
	if batchStart < 0 {
		t.Fatal("REST batch rate-limit block missing")
	}
	if got := strings.Count(conf[batchStart:], `SecRule REQUEST_METHOD "@streq POST"`); got != 2 {
		t.Errorf("found %d batch POST guards, want 2", got)
	}
	if got := strings.Count(conf[batchStart:], "t:none,t:urlDecodeUni"); got != 2 {
		t.Errorf("found %d batch URI normalizers, want 2", got)
	}
	const incrementGuard = "SecRule REQUEST_METHOD \"@streq POST\" \\\n" +
		"    \"setvar:ip.batch_count=+1,expirevar:ip.batch_count=60\""
	if !strings.Contains(conf[batchStart:], incrementGuard) {
		t.Error("batch counter update is not guarded by the final POST chain rule")
	}
	patterns := regexp.MustCompile(`SecRule REQUEST_URI "@rx ([^"]+)"`).FindAllStringSubmatch(conf[batchStart:], -1)
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
