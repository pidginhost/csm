package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Enabling the OWASP CRS vendor set exposes rule IDs the confidence table did
// not carry. An unclassified rule is escalation-eligible by design, which
// fails secure, but it also raises modsec_classifier_gap on every hit -- so a
// protocol-enforcement rule that fires on any unusual-but-legitimate request
// becomes a recurring warning the operator cannot resolve without editing the
// table themselves.
//
// Messages below are taken verbatim from a production audit log, as the table
// requires: exact, fixture-verified IDs rather than a range.
func TestClassifyModSecCRSPolicyRules(t *testing.T) {
	tests := []struct {
		name string
		id   int
		msg  string
		tags string
		want modsecConfidence
	}{
		// Protocol enforcement: an odd request line is as often a broken
		// client or a proxy as an attack.
		{"920100 invalid request line", 920100, "Invalid HTTP Request Line", "", modsecConfLow},
		// Says "by policy" in its own message, but the existing wording match
		// is for "not allowed by policy" and this reads "restricted by policy".
		{"920440 restricted extension", 920440, "URL file extension is restricted by policy", "", modsecConfLow},

		// Already covered before this change; kept so the additions cannot
		// quietly widen into rules that carry real attack evidence.
		{"920340 missing content-type", 920340, "Request Containing Content, but Missing Content-Type header", "", modsecConfLow},
		{"949110 anomaly score", 949110, "Inbound Anomaly Score Exceeded (Total Score: 10)", "", modsecConfLow},
		{"942100 sqli stays high", 942100, "SQL Injection Attack Detected via libinjection", "", modsecConfHigh},
		{"930100 traversal stays high", 930100, "Path Traversal Attack (/../)", "", modsecConfHigh},
		{"913100 scanner stays high", 913100, "Found User-Agent associated with security scanner", "", modsecConfHigh},
		{"930120 os file access stays high by tag", 930120, "OS File Access Attempt", "attack-lfi", modsecConfHigh},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyModSecConfidence(tc.id, tc.msg, tc.tags, ""); got != tc.want {
				t.Errorf("classifyModSecConfidence(%d, %q, %q) = %v, want %v", tc.id, tc.msg, tc.tags, got, tc.want)
			}
		})
	}
}

// An attack signal in the message must still override a low-confidence ID, so
// adding policy rules cannot mask a rule that later carries real evidence.
func TestClassifyModSecAttackEvidenceOverridesLowID(t *testing.T) {
	if got := classifyModSecConfidence(920100, "Invalid HTTP Request Line: SQL Injection Attack Detected", "", ""); got != modsecConfHigh {
		t.Errorf("attack evidence did not override the low-confidence ID: got %v", got)
	}
}

// LiteSpeed's mod_security front-end logs only the rule ID and the rule file,
// never msg or tag. OWASP CRS names its rule files after the attack class
// ("REQUEST-942-APPLICATION-ATTACK-SQLI.conf"), so the file carries the same
// evidence the tag would have. Without it every CRS attack rule on LiteSpeed
// is unknown and raises modsec_classifier_gap on each hit.
func TestClassifyModSecCRSAttackRuleFile(t *testing.T) {
	tests := []struct {
		name string
		id   int
		file string
		want modsecConfidence
	}{
		{"sqli file", 942190, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", modsecConfHigh},
		{"lfi file", 930100, "REQUEST-930-APPLICATION-ATTACK-LFI.conf", modsecConfHigh},
		{"php file", 933160, "REQUEST-933-APPLICATION-ATTACK-PHP.conf", modsecConfHigh},
		{"xss file", 941300, "REQUEST-941-APPLICATION-ATTACK-XSS.conf", modsecConfHigh},
		// Protocol enforcement is not attack evidence: it stays unknown so a
		// real gap is still reported.
		{"protocol enforcement stays unknown", 920170, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf", modsecConfUnknown},
		// A known low-confidence ID is not upgraded by a file it does not
		// live in.
		{"anomaly evaluation stays low", 949110, "REQUEST-949-BLOCKING-EVALUATION.conf", modsecConfLow},
		{"no file stays unknown", 942190, "", modsecConfUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyModSecConfidence(tc.id, "", "", tc.file); got != tc.want {
				t.Errorf("classifyModSecConfidence(%d, file=%q) = %v, want %v", tc.id, tc.file, got, tc.want)
			}
		})
	}
}

// liteSpeedTriggerLineCRSSQLi is a CRS attack rule as LiteSpeed logs it: rule
// ID and file path only.
const liteSpeedTriggerLineCRSSQLi = `2026-05-09 09:07:53.866619 [NOTICE] [1800848] [T4] [203.0.113.63:62060-H3:1FDA31C803B1F23A-44#APVH_test.example.com:443] [MODSEC] mod_security rule [id "942190"] at [/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf:59] triggered!`

func TestLiteSpeedCRSAttackRuleIsHighNotGap(t *testing.T) {
	resetModSecState()
	installModSecRegistryForTest(t, map[int]string{942190: "deny"})

	findings := parseModSecLogLineDeduped(liteSpeedTriggerLineCRSSQLi, &config.Config{})
	sawBlock := false
	for _, f := range findings {
		switch f.Check {
		case "modsec_classifier_gap":
			t.Fatalf("CRS attack rule identified by its rule file raised a classifier gap: %s", f.Message)
		case "modsec_block_realtime":
			sawBlock = true
			if f.Severity != alert.High {
				t.Errorf("CRS attack block severity = %v, want High", f.Severity)
			}
		}
	}
	if !sawBlock {
		t.Fatal("expected a modsec_block_realtime finding")
	}
}

func TestExtractModSecRuleFile(t *testing.T) {
	tests := []struct {
		name, line, want string
	}{
		{"litespeed", liteSpeedTriggerLineCRSSQLi, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"},
		{"apache", `[Wed May 09 09:07:53.866619 2026] [security2:error] [pid 1] [client 203.0.113.64:5555] ModSecurity: Access denied with code 403 (phase 2). [file "/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf"] [line "44"] [id "930100"]`, "REQUEST-930-APPLICATION-ATTACK-LFI.conf"},
		{"none", `[MODSEC] mod_security rule [id "942190"] triggered!`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractModSecRuleFile(tc.line); got != tc.want {
				t.Errorf("extractModSecRuleFile() = %q, want %q", got, tc.want)
			}
		})
	}
}
