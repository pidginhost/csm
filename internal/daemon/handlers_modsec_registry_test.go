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

func TestLiteSpeedTriggered_UnknownRuleDefaultsToBlock(t *testing.T) {
	// Empty registry on purpose: the registry-build path may not yet have
	// run on a fresh install, and the legacy behaviour of defaulting to
	// block must be preserved so we never silently drop coverage.
	installModSecRegistryForTest(t, map[int]string{})

	findings := parseModSecLogLine(liteSpeedTriggerLine949110, &config.Config{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Check != "modsec_block_realtime" {
		t.Errorf("check = %q, want modsec_block_realtime (unknown rule defaults to block)", findings[0].Check)
	}
}

func TestLiteSpeedTriggered_NilRegistryDefaultsToBlock(t *testing.T) {
	prev := modsec.Global()
	modsec.SetGlobal(nil)
	t.Cleanup(func() { modsec.SetGlobal(prev) })

	findings := parseModSecLogLine(liteSpeedTriggerLine949110, &config.Config{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Check != "modsec_block_realtime" {
		t.Errorf("check = %q, want modsec_block_realtime (nil registry defaults to block)", findings[0].Check)
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

// TestLiteSpeedDenyActionStillEscalates ensures registry-aware classification
// did not regress the legitimate deny-rule escalation path.
func TestLiteSpeedDenyActionStillEscalates(t *testing.T) {
	resetModSecState()
	installModSecRegistryForTest(t, map[int]string{949110: "deny"})

	cfg := &config.Config{}
	escalated := false
	for i := 0; i < modsecDefaultEscalationHits+1; i++ {
		findings := parseModSecLogLineDeduped(liteSpeedTriggerLine949110, cfg)
		for _, f := range findings {
			if f.Check == "modsec_block_escalation" {
				escalated = true
			}
		}
	}
	if !escalated {
		t.Fatal("deny-action rule did not escalate after threshold hits")
	}
}
