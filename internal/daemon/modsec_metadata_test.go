package daemon

import (
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Both engines can expand request text in msg. Its words must not change
// confidence, even when they never resemble a bracketed log field.
func TestModSecMacroTextCannotChangeConfidence(t *testing.T) {
	for _, engine := range []string{"v2", "v3"} {
		for _, tc := range []struct {
			name, actions, message, tags string
			id                           int
			wantSeverity                 alert.Severity
			wantEscalation, wantGap      bool
		}{
			{"unknown policy words", "deny,msg:'Custom hit %{MATCHED_VAR}'", "Custom hit anomaly score exceeded", "", 1001, alert.Warning, true, true},
			{"unknown policy tags", "deny,tag:'%{MATCHED_VAR}'", "", "anomaly-evaluation", 1001, alert.Warning, true, true},
			{"unknown attack words", "deny,msg:'Custom hit %{MATCHED_VAR}'", "Custom hit SQL injection", "", 1001, alert.Warning, true, true},
			{"known low attack words", "deny,msg:'Inbound anomaly score exceeded %{MATCHED_VAR}'", "Inbound anomaly score exceeded SQL injection", "", 949110, alert.Warning, false, false},
			{"known low attack tags", "deny,tag:'%{MATCHED_VAR}'", "", "attack-sqli", 949110, alert.Warning, false, false},
			{"configured policy", "deny,msg:'Request content type not allowed by policy: %{MATCHED_VAR}'", "Request content type not allowed by policy: SQL injection", "", 1001, alert.Warning, false, false},
			{"configured attack", "deny,msg:'SQL injection: %{MATCHED_VAR}'", "SQL injection: anomaly score exceeded", "", 1001, alert.High, true, false},
			{"configured attack tag", "deny,msg:'Custom hit %{MATCHED_VAR}',tag:'attack-sqli'", "Custom hit anomaly score exceeded", "attack-sqli", 1001, alert.High, true, false},
		} {
			t.Run(engine+"/"+tc.name, func(t *testing.T) {
				resetModSecState()
				t.Cleanup(resetModSecState)
				installModSecRegistryForTest(t, map[int]string{tc.id: tc.actions})
				line := modsecV3ValueLine("203.0.113.75", "probe")
				if engine == "v2" {
					line = modsecV2CookieLine("203.0.113.75", "probe")
					line = strings.ReplaceAll(line, "942100", "1001")
					line = strings.ReplaceAll(line, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "custom.conf")
					line = strings.ReplaceAll(line, "SQL Injection Attack Detected via libinjection", "Custom hit")
					line = strings.ReplaceAll(line, "attack-sqli", "custom-tag")
				}
				line = strings.Replace(line, `[id "1001"]`, `[id "`+strconv.Itoa(tc.id)+`"]`, 1)
				line = strings.Replace(line, `[msg "Custom hit"]`, `[msg "`+tc.message+`"]`, 1)
				line = strings.Replace(line, `[tag "custom-tag"]`, `[tag "`+tc.tags+`"]`, 1)
				base := parseModSecLogLine(line, &config.Config{})
				if len(base) != 1 || base[0].Severity != tc.wantSeverity {
					t.Fatalf("base findings = %+v, want one with severity %v", base, tc.wantSeverity)
				}
				if !strings.Contains(base[0].Details, "Message: "+tc.message+"\n") {
					t.Fatalf("display lost the logged message: %q", base[0].Details)
				}
				seen := modsecFindingChecks(&config.Config{}, []string{line, line, line})
				if seen["modsec_block_escalation"] != tc.wantEscalation || seen["modsec_classifier_gap"] != tc.wantGap || seen["modsec_low_confidence_burst"] == tc.wantEscalation {
					t.Fatalf("findings = %v, want escalation=%v gap=%v", seen, tc.wantEscalation, tc.wantGap)
				}
			})
		}
	}
}

func TestModSecMissingMetadataCannotTrustLogKeywords(t *testing.T) {
	for _, actions := range []map[int]string{nil, {1002: "deny"}} {
		t.Run("missing", func(t *testing.T) {
			resetModSecState()
			t.Cleanup(resetModSecState)
			installModSecRegistryForTest(t, actions)
			line := strings.Replace(modsecV3ValueLine("203.0.113.76", "probe"), "Custom hit", "Custom hit anomaly score exceeded", 1)
			seen := modsecFindingChecks(&config.Config{}, []string{line, line, line})
			if !seen["modsec_block_escalation"] || !seen["modsec_classifier_gap"] || seen["modsec_low_confidence_burst"] {
				t.Fatalf("missing metadata trusted log keywords: %v", seen)
			}
		})
	}
}

func TestModSecLiteSpeedUsesConfiguredMetadata(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	installModSecRegistryForTest(t, map[int]string{1001: "deny,msg:'SQL injection: %{MATCHED_VAR}'"})
	line := strings.Replace(liteSpeedTriggerLine210710, `[id "210710"]`, `[id "1001"]`, 1)
	base := parseModSecLogLine(line, &config.Config{})
	if len(base) != 1 || base[0].Check != "modsec_block_realtime" || base[0].Severity != alert.High {
		t.Fatalf("native LiteSpeed lost configured confidence: %+v", base)
	}
	seen := modsecFindingChecks(&config.Config{}, []string{line, line, line})
	if !seen["modsec_block_escalation"] || seen["modsec_classifier_gap"] || seen["modsec_low_confidence_burst"] {
		t.Fatalf("native LiteSpeed findings = %v", seen)
	}
}
