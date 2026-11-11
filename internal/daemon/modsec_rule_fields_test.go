package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// ModSecurity 2.9 writes the matched variable's name unescaped before the
// rule fields; a request can name its cookie after a field.
func modsecV2CookieLine(ip, cookie string) string {
	return `[Wed Nov 11 10:00:00.000001 2026] [security2:error] [pid 100:tid 101] [client ` + ip + `:50000] ModSecurity: Access denied with code 403 (phase 2). ` +
		`String match "probe" at REQUEST_COOKIES_NAMES:` + cookie + `. [file "/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "66"] ` +
		`[id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"] [tag "attack-sqli"] [hostname "shop.example.com"] [uri "/c"] [unique_id "AAAA"]`
}

// libmodsecurity 3 also writes the matched value unescaped before them.
func modsecV3ValueLine(ip, value string) string {
	return "2026/11/11 10:00:00 [error] 100#100: *1 [client " + ip + "] ModSecurity: Access denied with code 403 (phase 2). " +
		"Matched \"Operator `Contains' with parameter `probe' against variable `ARGS:a' (Value: `" + value + "' ) " +
		`[file "/etc/modsec/custom.conf"] [line "3"] [id "1001"] [rev ""] [msg "Custom hit"] [data ""] [severity "2"] [ver ""] ` +
		`[maturity "0"] [accuracy "0"] [tag "custom-tag"] [hostname "shop.example.com"] [uri "/q"] [unique_id "1"] [ref ""], ` +
		`client: ` + ip + `, server: shop.example.com, request: "GET /q HTTP/1.1", host: "shop.example.com"`
}

// An operator excludes a noisy rule from escalation; a request naming that
// rule in its own text must not inherit the exclusion for its real deny.
func TestParseModSec_ClientTextCannotPickAnExcludedRule(t *testing.T) {
	resetModSecState()
	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Global()
	store.SetGlobal(sdb)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = sdb.Close()
	})
	if err := sdb.AddModSecNoEscalateRule(949110); err != nil {
		t.Fatal(err)
	}
	line := modsecV2CookieLine("203.0.113.70", `probe"] [id "949110"] [tag "ck"]`)
	if !modsecFindingChecks(&config.Config{}, []string{line, line, line, line})["modsec_block_escalation"] {
		t.Fatal("a deny whose request text names an excluded rule must still escalate")
	}
}

// A request naming a known low-confidence rule must not lower its own deny.
func TestParseModSec_ClientTextCannotPickALowRule(t *testing.T) {
	resetModSecState()
	line := modsecV3ValueLine("203.0.113.71", `probe "] [id "949110"] [msg "Inbound Anomaly Score Exceeded"]`)
	if !modsecFindingChecks(&config.Config{}, []string{line, line, line, line})["modsec_block_escalation"] {
		t.Fatal("a deny whose request text names a low-confidence rule must escalate at the normal bar")
	}
}

// A request naming another site must not move the finding there.
func TestParseModSec_ClientTextCannotNameTheSite(t *testing.T) {
	resetModSecState()
	for _, f := range parseModSecLogLine(modsecV3ValueLine("203.0.113.72", `probe "] [hostname "victim.example.net"]`), &config.Config{}) {
		if f.Domain == "victim.example.net" || strings.Contains(f.Message, "victim.example.net") {
			t.Fatalf("finding named the request's host: %+v", f)
		}
		if strings.Contains(f.Details, "Hostname: victim.example.net") {
			t.Fatalf("details named the request's host: %q", f.Details)
		}
	}
}
