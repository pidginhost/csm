package modsec

import (
	"reflect"
	"testing"
)

// Synthetic lines shaped like the error-log entries ModSecurity 2.9
// (Apache), libmodsecurity 3 (nginx connector) and LiteSpeed write. v2 leaves
// the matched variable's name unescaped before the rule fields; v3 also
// leaves the matched value, macro-expanded messages and the URI unescaped.
const (
	ruleTestV2 = `[Wed Nov 11 10:00:00.000001 2026] [security2:error] [pid 100:tid 101] [client 203.0.113.60:50000] ModSecurity: Access denied with code 403 (phase 2). ` +
		`String match "probe" at REQUEST_COOKIES_NAMES:probe. [file "/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "66"] [id "942100"] ` +
		`[msg "Custom hit probe\\"] [id \\"949110\\"]"] [data "Matched Data: probe\\x22] [id \\x22949110\\x22]"] [severity "CRITICAL"] ` +
		`[tag "application-multi"] [tag "attack-sqli"] [hostname "192.0.2.10"] [uri "/c\\"] [tag \\"x\\"]"] [unique_id "AAAA"]`
	ruleTestV3 = "2026/11/11 10:00:00 [error] 100#100: *1 [client 203.0.113.61] ModSecurity: Access denied with code 403 (phase 2). " +
		"Matched \"Operator `Contains' with parameter `probe' against variable `ARGS:a' (Value: `probe' ) " +
		`[file "/usr/share/modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "66"] [id "942100"] [rev ""] ` +
		`[msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: probe found within ARGS:a: probe \x22"] [severity "2"] ` +
		`[ver "OWASP_CRS/3.3.8"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "attack-sqli"] [hostname "192.0.2.10"] ` +
		`[uri "/q"] [unique_id "179443541352.069988"] [ref "o0,5v9,5"], client: 203.0.113.61, server: example.com, request: "GET /q?a=probe HTTP/1.1", host: "example.com"`
	ruleTestLiteSpeed = `2026-11-11 10:00:00.000000 [INFO] [100] [T0] [203.0.113.62:50000-1#APVH_example.com:443] [MODSEC] mod_security rule [id "214930"] ` +
		`at [/etc/apache2/conf.d/modsec_vendor_configs/comodo_litespeed/30_Apps_OtherApps.conf:12] triggered!`
)

func TestErrorLogRuleReadsServerFields(t *testing.T) {
	sqli := LogRule{
		ID: "942100", File: "/usr/share/modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
		Msg: "SQL Injection Attack Detected via libinjection", Tags: []string{"application-multi", "attack-sqli"},
		Hostname: "192.0.2.10", URI: "/q",
	}
	v2 := LogRule{
		ID: "942100", File: "/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
		Msg: `Custom hit probe\\`, Tags: []string{"application-multi", "attack-sqli"},
		Hostname: "192.0.2.10", URI: `/c\\`,
	}
	for _, tt := range []struct {
		name, line string
		want       LogRule
	}{
		{"v3", ruleTestV3, sqli},
		// v2 escapes client quotes inside msg, data and uri, so the text
		// there cannot open a field.
		{"v2 escaped client quotes", ruleTestV2, v2},
		{"litespeed", ruleTestLiteSpeed, LogRule{ID: "214930", File: "/etc/apache2/conf.d/modsec_vendor_configs/comodo_litespeed/30_Apps_OtherApps.conf"}},
		{"v2 without data or severity",
			`[Wed Nov 11 10:00:00.000001 2026] [security2:error] [pid 100:tid 101] [client 203.0.113.60:50000] ModSecurity: Warning. Operator GE matched 5 at TX:inbound_anomaly_score. ` +
				`[file "/etc/modsecurity/rules/RESPONSE-980-CORRELATION.conf"] [line "92"] [id "980130"] [msg "Inbound Anomaly Score Exceeded"] [ver "OWASP_CRS/3.3.8"] ` +
				`[tag "event-correlation"] [hostname "192.0.2.10"] [uri "/s"] [unique_id "AAAA"]`,
			LogRule{ID: "980130", File: "/etc/modsecurity/rules/RESPONSE-980-CORRELATION.conf", Msg: "Inbound Anomaly Score Exceeded",
				Tags: []string{"event-correlation"}, Hostname: "192.0.2.10", URI: "/s"}},
		{"unclosed and empty values",
			`[Wed Nov 11 10:00:00.000001 2026] [security2:error] [pid 100:tid 101] [client 203.0.113.60:50000] ModSecurity: Warning. [id ""] [msg "unclosed`,
			LogRule{}},
		{"no rule fields", `[Wed Nov 11 10:00:00.000001 2026] [security2:notice] [pid 100:tid 101] ModSecurity: Status engine is currently disabled.`, LogRule{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ErrorLogRule(tt.line)
			if !ok || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ErrorLogRule = %#v, %v; want %#v, true", got, ok, tt.want)
			}
		})
	}
}

// Client text that forms a rule field makes the line's rule unknowable: the
// server's own fields are still there, but nothing tells them apart.
func TestErrorLogRuleRefusesClientFormedFields(t *testing.T) {
	v3 := func(value, msg, uri string) string {
		return "2026/11/11 10:00:00 [error] 100#100: *1 [client 203.0.113.61] ModSecurity: Access denied with code 403 (phase 2). " +
			"Matched \"Operator `Contains' with parameter `probe' against variable `ARGS:a' (Value: `" + value + "' ) " +
			`[file "/etc/modsec/rules.conf"] [line "3"] [id "1001"] [rev ""] [msg "` + msg + `"] [data ""] [severity "2"] [ver ""] ` +
			`[maturity "0"] [accuracy "0"] [tag "custom-tag"] [hostname "192.0.2.10"] [uri "` + uri + `"] [unique_id "1"] [ref ""]`
	}
	v2 := func(name string) string {
		return `[Wed Nov 11 10:00:00.000001 2026] [security2:error] [pid 100:tid 101] [client 203.0.113.60:50000] ModSecurity: Access denied with code 403 (phase 2). ` +
			`String match "probe" at REQUEST_COOKIES_NAMES:` + name + `. [file "/etc/modsec/rules.conf"] [line "3"] [id "1001"] [severity "CRITICAL"] ` +
			`[tag "custom-tag"] [hostname "192.0.2.10"] [uri "/c"] [unique_id "AAAA"]`
	}
	for _, tt := range []struct{ name, line string }{
		{"v3 value names a rule", v3(`probe "] [id "949110"] [msg "x"]`, "Custom hit", "/q")},
		{"v3 value names a host", v3(`probe "] [hostname "victim.example.net"]`, "Custom hit", "/q")},
		{"v3 value adds a tag", v3(`probe "] [tag "attack-sqli"]`, "Custom hit", "/q")},
		{"v3 message adds a tag", v3("probe", `Custom hit probe"] [tag "anomaly-evaluation"]`, "/q")},
		{"v3 message names a rule", v3("probe", `Custom hit "] [id "949110"]`, "/q")},
		{"v3 uri adds a tag", v3("probe", "Custom hit", `/q"] [tag "x"]`)},
		{"v3 uri names a rule", v3("probe", "Custom hit", `/q"] [id "949110"]`)},
		{"v2 variable name names a rule", v2(`probe"] [id "949110"] [tag "ck"]`)},
		// The real line has no msg; one placed before the rule's id is client text.
		{"v2 variable name adds a message", v2(`probe"] [msg "Inbound Anomaly Score Exceeded"]`)},
		{"v2 variable name adds a file", v2(`probe"] [file "/x/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"]`)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got, ok := ErrorLogRule(tt.line); ok {
				t.Fatalf("ErrorLogRule = %#v, true; want ambiguous", got)
			}
		})
	}
}
