package webui

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Structured details keep the raw line, whose request text can imitate any
// field. When the handler stored no rule for a line, the raw line must not
// supply one.
func TestModSecStructuredDetailsDoNotFallBackToRawFields(t *testing.T) {
	f := alert.Finding{Details: "Rule: \nMessage: \nHostname: \nURI: \nRaw: [client 203.0.113.70] ModSecurity: Access denied " +
		`String match "probe" at REQUEST_COOKIES_NAMES:probe"] [id "900122"] [msg "x"] [hostname "victim.example.net"] [uri "/v"]. [id "942100"]`}
	if got := extractModSecRule(f); got != "" {
		t.Errorf("rule = %q, want none", got)
	}
	if got := extractModSecDescription(f); got != "" {
		t.Errorf("description = %q, want none", got)
	}
	if got := extractModSecHostname(f); got != "" {
		t.Errorf("hostname = %q, want none", got)
	}
	if got := extractModSecURI(f); got != "" {
		t.Errorf("uri = %q, want none", got)
	}
}

// Escalation findings keep only the raw line; one whose request text
// imitates rule fields names no rule in the stats.
func TestModSecRawDetailsRefuseImitatedFields(t *testing.T) {
	f := alert.Finding{Details: `[Wed Nov 11 10:00:00.000001 2026] [security2:error] [pid 100:tid 101] [client 203.0.113.70:50000] ModSecurity: Access denied with code 403 (phase 2). ` +
		`String match "probe" at REQUEST_COOKIES_NAMES:probe"] [id "900122"] [hostname "victim.example.net"]. [file "/etc/modsec/rules.conf"] [line "3"] [id "942100"] ` +
		`[severity "CRITICAL"] [hostname "shop.example.com"] [uri "/c"] [unique_id "AAAA"]`}
	if got := extractModSecRule(f); got != "" {
		t.Errorf("rule = %q, want none", got)
	}
	if got := extractModSecHostname(f); got != "" {
		t.Errorf("hostname = %q, want none", got)
	}
}
