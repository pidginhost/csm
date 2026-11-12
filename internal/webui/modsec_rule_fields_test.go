package webui

import (
	"strings"
	"testing"
	"time"

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

func TestModSecTruncatedRawDetailsDoNotSupplyFields(t *testing.T) {
	// Older escalation findings kept only this prefix of the full log line.
	// The real fields that expose the forgery occur beyond the retained text.
	line := `[client 203.0.113.70] ModSecurity: Access denied with code 403. String match "probe" at REQUEST_COOKIES_NAMES:probe"] ` +
		`[id "900122"] [msg "forged"] [hostname "example.com"] [uri "/forged"] [unique_id "fake"] [ref ""] ` + strings.Repeat("x", 400)
	f := alert.Finding{Details: line[:400] + "..."}
	for name, extract := range map[string]func(alert.Finding) string{
		"rule": extractModSecRule, "description": extractModSecDescription,
		"hostname": extractModSecHostname, "uri": extractModSecURI,
	} {
		if got := extract(f); got != "" {
			t.Errorf("%s = %q, want unknown", name, got)
		}
	}
	if ip := extractModSecIP(f); ip != "203.0.113.70" {
		t.Errorf("client IP = %q, want server-written address", ip)
	}
}

// Older escalation findings keep only the raw line; one whose request text
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

func TestModSecValidatedDetailsKeepEscalationsSeparate(t *testing.T) {
	for _, rule := range []string{"942100", ""} {
		for _, escalationFirst := range []bool{false, true} {
			base := alert.Finding{
				Check: "modsec_block_realtime", SourceIP: "203.0.113.70", Timestamp: time.Unix(1700000000, 0),
				Details: "Rule: " + rule + "\nMessage: \nHostname: \nURI: \nRaw: truncated...",
			}
			escalation := base
			escalation.Check = "modsec_block_escalation"
			escalation.Severity = alert.Critical
			findings := []alert.Finding{base, base, escalation}
			if escalationFirst {
				findings = []alert.Finding{escalation, base, base}
			}
			got := deduplicateModSecFindings(findings)
			counts := map[string]int{}
			for _, f := range got {
				counts[f.Check]++
			}
			if len(got) != 2 || counts[base.Check] != 1 || counts[escalation.Check] != 1 {
				t.Errorf("rule %q, escalationFirst %v: findings = %v", rule, escalationFirst, counts)
			}
		}
	}
}
