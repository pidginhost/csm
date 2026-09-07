package daemon

import "testing"

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
			if got := classifyModSecConfidence(tc.id, tc.msg, tc.tags); got != tc.want {
				t.Errorf("classifyModSecConfidence(%d, %q, %q) = %v, want %v", tc.id, tc.msg, tc.tags, got, tc.want)
			}
		})
	}
}

// An attack signal in the message must still override a low-confidence ID, so
// adding policy rules cannot mask a rule that later carries real evidence.
func TestClassifyModSecAttackEvidenceOverridesLowID(t *testing.T) {
	if got := classifyModSecConfidence(920100, "Invalid HTTP Request Line: SQL Injection Attack Detected", ""); got != modsecConfHigh {
		t.Errorf("attack evidence did not override the low-confidence ID: got %v", got)
	}
}
