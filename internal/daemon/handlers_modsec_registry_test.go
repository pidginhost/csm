package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/modsec"
)

// installModSecRegistryForTest seeds the package-level registry by writing
// a synthetic conf file and running the real BuildRegistry. Using the
// public path keeps the test indistinguishable from production behaviour.
func installModSecRegistryForTest(t *testing.T, actions map[int]string) {
	t.Helper()
	prev := modsec.Global()

	dir := t.TempDir()
	var sb strings.Builder
	for id, action := range actions {
		fmt.Fprintf(&sb, `SecRule REQUEST_URI "x" "id:%d,phase:1,%s`, id, action)
		if action == "deny" {
			sb.WriteString(",status:403")
		}
		sb.WriteString("\"\n")
	}
	confPath := filepath.Join(dir, "seed.conf")
	if err := os.WriteFile(confPath, []byte(sb.String()), 0644); err != nil {
		t.Fatalf("write seed conf: %v", err)
	}
	reg, err := modsec.BuildRegistry([]string{dir})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	modsec.SetGlobal(reg)

	t.Cleanup(func() { modsec.SetGlobal(prev) })
}

// LiteSpeed log line for rule 210710 (Comodo CWAF pass-action). RFC 5737
// documentation IP per the project's no-real-IPs-in-tests rule.
const liteSpeedTriggerLine210710 = `2026-05-09 09:07:53.866619 [NOTICE] [1800848] [T4] [203.0.113.61:62060-H3:1FDA31C803B1F23A-44#APVH_test.example.com:443] [MODSEC] mod_security rule [id "210710"] at [/etc/apache2/conf.d/modsec_vendor_configs/comodo_litespeed/02_Global_Generic.conf:46] triggered!`

// LiteSpeed log line for rule 949110 (CRS-style deny). Different IP so
// escalation tests don't see dedup hits across cases.
const liteSpeedTriggerLine949110 = `2026-05-09 09:07:53.866619 [NOTICE] [1800848] [T4] [203.0.113.62:62060-H3:1FDA31C803B1F23A-44#APVH_test.example.com:443] [MODSEC] mod_security rule [id "949110"] at [/etc/apache2/conf.d/modsec_vendor_configs/owasp/REQUEST-949-BLOCKING-EVALUATION.conf:80] triggered!`

func TestLiteSpeedTriggered_PassActionRuleClassifiedAsWarning(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{210710: "pass"})

	findings := parseModSecLogLine(liteSpeedTriggerLine210710, &config.Config{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Check != "modsec_warning_realtime" {
		t.Errorf("check = %q, want modsec_warning_realtime (rule 210710 is pass-action)", findings[0].Check)
	}
}

func TestLiteSpeedTriggered_DenyActionRuleClassifiedAsBlock(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{949110: "deny"})

	findings := parseModSecLogLine(liteSpeedTriggerLine949110, &config.Config{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Check != "modsec_block_realtime" {
		t.Errorf("check = %q, want modsec_block_realtime (rule 949110 is deny-action)", findings[0].Check)
	}
}

func TestLiteSpeedTriggered_EmptyRegistryDoesNotEscalate(t *testing.T) {
	// An empty registry means CSM has no rule-action knowledge at all: the
	// build has not run yet, or the vendor rule tree was transiently empty
	// (cPanel modsec_assemble mid-rewrite, or a boot-time web-server
	// mis-detection). In that state it cannot tell a pass-action scoring rule
	// from a real deny, so an ambiguous "triggered" line must NOT be
	// classified as a block -- doing so false-escalated benign Comodo CWAF
	// rules (210710/214930) into 24h auto-bans of real visitors. Explicit
	// "Access denied" lines are still classified as blocks upstream; a
	// LiteSpeed deny that logs only "triggered!" is degraded to warning until
	// a refresh loads rule actions again.
	installModSecRegistryForTest(t, map[int]string{})

	findings := parseModSecLogLine(liteSpeedTriggerLine949110, &config.Config{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Check != "modsec_warning_realtime" {
		t.Errorf("check = %q, want modsec_warning_realtime (empty registry must not escalate)", findings[0].Check)
	}
}

func TestApacheAccessDenied_EmptyRegistryStillBlocks(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{})

	line := `[Wed Apr 01 15:15:05.234401 2026] [error] [client 198.51.100.164] ModSecurity: Access denied with code 403, [id "949110"] [msg "Inbound Anomaly Score Exceeded"] [hostname "www.example.com"] [uri "/xmlrpc.php"]`
	findings := parseModSecLogLine(line, &config.Config{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Check != "modsec_block_realtime" {
		t.Errorf("check = %q, want modsec_block_realtime (Access denied does not depend on registry)", findings[0].Check)
	}
}

func TestLiteSpeedTriggered_UnknownRuleInPopulatedRegistryDefaultsToBlock(t *testing.T) {
	// When the registry IS populated, a genuinely unrecognised rule stays
	// conservative and classifies as a block so an unknown deny rule still
	// escalates. Rule 210710 is absent from this registry.
	installModSecRegistryForTest(t, map[int]string{949110: "deny"})

	findings := parseModSecLogLine(liteSpeedTriggerLine210710, &config.Config{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Check != "modsec_block_realtime" {
		t.Errorf("check = %q, want modsec_block_realtime (unknown rule in a populated registry stays conservative)", findings[0].Check)
	}
}

func TestLiteSpeedTriggered_NilRegistryDoesNotEscalate(t *testing.T) {
	// No registry installed at all: same reasoning as the empty-registry
	// case -- without rule-action knowledge, ambiguous "triggered" lines must
	// not be auto-escalated into blocks.
	prev := modsec.Global()
	modsec.SetGlobal(nil)
	t.Cleanup(func() { modsec.SetGlobal(prev) })

	findings := parseModSecLogLine(liteSpeedTriggerLine949110, &config.Config{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Check != "modsec_warning_realtime" {
		t.Errorf("check = %q, want modsec_warning_realtime (nil registry must not escalate)", findings[0].Check)
	}
}

// TestLiteSpeedPassActionDoesNotEscalate is the regression guard for the
// real-world false-block: three pass-action triggers from the same IP
// inside the escalation window must NOT promote to modsec_block_escalation.
func TestLiteSpeedPassActionDoesNotEscalate(t *testing.T) {
	resetModSecState()
	installModSecRegistryForTest(t, map[int]string{210710: "pass"})

	cfg := &config.Config{}
	for i := 0; i < modsecDefaultEscalationHits+1; i++ {
		findings := parseModSecLogLineDeduped(liteSpeedTriggerLine210710, cfg)
		for _, f := range findings {
			if f.Check == "modsec_block_escalation" || f.Check == "modsec_csm_block_escalation" {
				t.Fatalf("pass-action rule escalated on hit %d: %+v", i+1, f)
			}
		}
	}
}

// TestLiteSpeedTriggered_RedirectActionClassifiedAsBlock guards the wider
// disposition set: redirect, proxy and pause divert the request away from
// the upstream application even though they are not literally "deny", so
// the classifier must treat them the same as a deny.
func TestLiteSpeedTriggered_RedirectActionClassifiedAsBlock(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{949110: "redirect"})

	findings := parseModSecLogLine(liteSpeedTriggerLine949110, &config.Config{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Check != "modsec_block_realtime" {
		t.Errorf("check = %q, want modsec_block_realtime (redirect is disruptive)", findings[0].Check)
	}
}

// liteSpeedTriggerLineUnknownDeny is a LiteSpeed "triggered!" line for a rule
// ID that is neither a CSM custom rule nor a known policy/anomaly rule, so the
// confidence classifier returns "unknown" (escalation-eligible at the normal
// bar). LiteSpeed lines carry only the rule ID and file path, no msg/tag.
const liteSpeedTriggerLineUnknownDeny = `2026-05-09 09:07:53.866619 [NOTICE] [1800848] [T4] [203.0.113.62:62060-H3:1FDA31C803B1F23A-44#APVH_test.example.com:443] [MODSEC] mod_security rule [id "211999"] at [/etc/apache2/conf.d/modsec_vendor_configs/comodo/rules.conf:80] triggered!`

// TestLiteSpeedDenyActionStillEscalates ensures registry-aware classification
// did not regress the legitimate deny-rule escalation path. The rule is
// "unknown" confidence, which remains escalation-eligible at the normal bar
// (a known policy/anomaly rule such as 949110 instead takes the low-confidence
// path; see TestParseModSec_CRSAnomalyIsLowNotHigh).
func TestLiteSpeedDenyActionStillEscalates(t *testing.T) {
	resetModSecState()
	installModSecRegistryForTest(t, map[int]string{211999: "deny"})

	cfg := &config.Config{}
	escalated := false
	for i := 0; i < modsecDefaultEscalationHits+1; i++ {
		findings := parseModSecLogLineDeduped(liteSpeedTriggerLineUnknownDeny, cfg)
		for _, f := range findings {
			if f.Check == "modsec_block_escalation" {
				escalated = true
			}
		}
	}
	if !escalated {
		t.Fatal("unknown deny-action rule did not escalate after threshold hits")
	}
}

func TestLiteSpeedUnknownPassActionSuppliesEvidenceToLowDenyBurst(t *testing.T) {
	resetModSecState()
	installModSecRegistryForTest(t, map[int]string{211999: "pass", 949110: "deny"})

	cfg := &config.Config{}
	seen := map[string]bool{}
	lines := []string{
		liteSpeedTriggerLineUnknownDeny,
		liteSpeedTriggerLine949110,
		liteSpeedTriggerLine949110,
		liteSpeedTriggerLine949110,
	}
	for _, line := range lines {
		for _, f := range parseModSecLogLineDeduped(line, cfg) {
			seen[f.Check] = true
		}
	}
	if !seen["modsec_classifier_gap"] {
		t.Fatal("unknown pass-action rule without msg/tag must raise classifier gap")
	}
	if !seen["modsec_block_escalation"] {
		t.Fatal("unknown pass-action evidence plus low-confidence denies must escalate")
	}
	if seen["modsec_low_confidence_burst"] {
		t.Fatal("unknown evidence must keep the burst out of the low-confidence-only path")
	}
}
