package daemon

import (
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestParseModSecLogLine_ApacheDeny(t *testing.T) {
	line := `[Wed Apr 01 15:15:05.234401 2026] [error] [client 173.244.42.164] ModSecurity: Access denied with code 403, [Rule: 'TX:content_type' '!@within %{tx.allowed_request_content_type}'] [id "920420"] [msg "Request content type is not allowed by policy"] [logdata "|text/html|"] [severity "CRITICAL"] [hostname "www.filmetari.com"] [uri "/xmlrpc.php"]`
	cfg := &config.Config{}

	findings := parseModSecLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Check != "modsec_block_realtime" {
		t.Errorf("check = %q, want modsec_block_realtime", f.Check)
	}
	if f.Severity != alert.High {
		t.Errorf("severity = %v, want High", f.Severity)
	}
	if !strings.Contains(f.Message, "173.244.42.164") {
		t.Errorf("message should contain IP, got %q", f.Message)
	}
	if !strings.Contains(f.Message, "920420") {
		t.Errorf("message should contain rule ID, got %q", f.Message)
	}
}

func TestParseModSecLogLine_CSMCustomRule(t *testing.T) {
	line := `[Wed Apr 01 17:13:54.047783 2026] [error] [client 185.177.72.61] ModSecurity: Access denied with code 403, [Rule: 'REQUEST_URI' '/\.env'] [id "900115"] [msg "CSM VP: Blocked .env file access"] [hostname "176.124.111.228"] [uri "/.env_sample"]`
	cfg := &config.Config{}

	findings := parseModSecLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Check != "modsec_block_realtime" {
		t.Errorf("check = %q, want modsec_block_realtime", f.Check)
	}
	if f.Severity != alert.High {
		t.Errorf("severity = %v, want High (CSM custom rule — block is informational)", f.Severity)
	}
	if !strings.Contains(f.Message, "900115") {
		t.Errorf("message should contain rule ID 900115, got %q", f.Message)
	}
}

func TestParseModSecLogLine_LiteSpeedTriggered(t *testing.T) {
	line := `2026-04-01 17:13:53.887905 [NOTICE] [2288689] [T1] [122.9.114.57:41920-13#APVH_*_cluster6.pidginhost.net] [MODSEC] mod_security rule [id "920170"] at [/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf:180] triggered!`
	cfg := &config.Config{}

	findings := parseModSecLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Check != "modsec_block_realtime" {
		t.Errorf("check = %q, want modsec_block_realtime", f.Check)
	}
	if f.Severity != alert.High {
		t.Errorf("severity = %v, want High (OWASP CRS)", f.Severity)
	}
	if !strings.Contains(f.Message, "122.9.114.57") {
		t.Errorf("message should contain IP, got %q", f.Message)
	}
}

func TestParseModSecLogLine_LiteSpeedWarning(t *testing.T) {
	line := `2026-04-01 17:13:53.887905 [NOTICE] [2288689] [T1] [122.9.114.57:41920-13#APVH_*_cluster6.pidginhost.net] [MODSEC] mod_security rule [id "920170"] at [/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf:180] matched`
	cfg := &config.Config{}

	findings := parseModSecLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Check != "modsec_warning_realtime" {
		t.Errorf("check = %q, want modsec_warning_realtime", f.Check)
	}
}

func TestParseModSecLogLine_NonModSecLine(t *testing.T) {
	line := `[Wed Apr 01 15:00:00 2026] [error] [client 10.0.0.1] File does not exist: /home/user/public_html/favicon.ico`
	cfg := &config.Config{}

	findings := parseModSecLogLine(line, cfg)
	if findings != nil {
		t.Errorf("expected nil for non-ModSecurity line, got %v", findings)
	}
}

func TestParseModSecLogLine_InfraIPSkipped(t *testing.T) {
	line := `[Wed Apr 01 15:15:05 2026] [error] [client 176.124.104.234] ModSecurity: Access denied with code 403, [id "900001"] [msg "test"] [hostname "test.com"] [uri "/test"]`
	cfg := &config.Config{}
	cfg.InfraIPs = []string{"176.124.104.234/32"}

	findings := parseModSecLogLine(line, cfg)
	if findings != nil {
		t.Errorf("expected nil for infra IP, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// Dedup + Escalation tests
// ---------------------------------------------------------------------------

func resetModSecState() {
	modsecDedup = sync.Map{}
	modsecCSMCounter = sync.Map{}
}

func TestModSecDedup(t *testing.T) {
	resetModSecState()

	line := `[Wed Apr 01 15:15:05.234401 2026] [error] [client 173.244.42.164] ModSecurity: Access denied with code 403, [Rule: 'TX:content_type' '!@within %{tx.allowed_request_content_type}'] [id "920420"] [msg "Request content type is not allowed by policy"] [logdata "|text/html|"] [severity "CRITICAL"] [hostname "www.filmetari.com"] [uri "/xmlrpc.php"]`
	cfg := &config.Config{}

	// First call — should return the base finding.
	f1 := parseModSecLogLineDeduped(line, cfg)
	if len(f1) != 1 {
		t.Fatalf("first call: expected 1 finding, got %d", len(f1))
	}
	if f1[0].Check != "modsec_block_realtime" {
		t.Errorf("first call: check = %q, want modsec_block_realtime", f1[0].Check)
	}

	// Second call (within 60s) — should be suppressed.
	f2 := parseModSecLogLineDeduped(line, cfg)
	if len(f2) != 0 {
		t.Errorf("second call: expected 0 findings (deduped), got %d: %v", len(f2), f2)
	}
}

func TestModSecCSMRuleEscalation(t *testing.T) {
	resetModSecState()

	// Same CSM rule line fired 3 times from the same IP.
	line := `[Wed Apr 01 17:13:54.047783 2026] [error] [client 185.177.72.61] ModSecurity: Access denied with code 403, [Rule: 'REQUEST_URI' '/\.env'] [id "900115"] [msg "CSM VP: Blocked .env file access"] [hostname "176.124.111.228"] [uri "/.env_sample"]`
	cfg := &config.Config{}

	// Call 1 — base finding, no escalation yet.
	f1 := parseModSecLogLineDeduped(line, cfg)
	hasEscalation := false
	for _, f := range f1 {
		if f.Check == "modsec_csm_block_escalation" {
			hasEscalation = true
		}
	}
	if hasEscalation {
		t.Error("call 1: should NOT have escalation finding yet")
	}

	// Call 2 — dedup suppresses base, no escalation yet.
	f2 := parseModSecLogLineDeduped(line, cfg)
	for _, f := range f2 {
		if f.Check == "modsec_csm_block_escalation" {
			t.Error("call 2: should NOT have escalation finding yet")
		}
	}

	// Call 3 — escalation threshold reached; escalation finding emitted
	// even though base finding is deduped.
	f3 := parseModSecLogLineDeduped(line, cfg)
	hasEscalation = false
	for _, f := range f3 {
		if f.Check == "modsec_csm_block_escalation" {
			hasEscalation = true
			if f.Severity != alert.Critical {
				t.Errorf("escalation severity = %v, want Critical", f.Severity)
			}
			if !strings.Contains(f.Message, "185.177.72.61") {
				t.Errorf("escalation message should contain IP, got %q", f.Message)
			}
		}
	}
	if !hasEscalation {
		t.Fatalf("call 3: expected escalation finding, got %v", f3)
	}
}

func TestModSecCRSNoEscalation(t *testing.T) {
	resetModSecState()

	cfg := &config.Config{}

	// 5 different CRS rule IDs from the same IP — none in the CSM 900000-900999 range.
	rules := []string{"920420", "920421", "920422", "920423", "920424"}
	for _, ruleID := range rules {
		line := `[Wed Apr 01 15:15:05 2026] [error] [client 10.20.30.40] ModSecurity: Access denied with code 403, [id "` + ruleID + `"] [msg "CRS rule hit"] [hostname "example.com"] [uri "/test"]`

		findings := parseModSecLogLineDeduped(line, cfg)
		for _, f := range findings {
			if f.Check == "modsec_csm_block_escalation" {
				t.Fatalf("CRS rule %s should NOT trigger escalation, but got: %v", ruleID, f)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Log path discovery tests
// ---------------------------------------------------------------------------

func TestDiscoverModSecLogPath_ConfigOverride(t *testing.T) {
	cfg := &config.Config{ModSecErrorLog: "/custom/path/error_log"}
	got := discoverModSecLogPath(cfg)
	if got != "/custom/path/error_log" {
		t.Errorf("want config override, got %q", got)
	}
}

func TestDiscoverModSecLogPath_AutoDiscovery(t *testing.T) {
	dir := t.TempDir()
	fakePath := dir + "/error_log"
	if err := os.WriteFile(fakePath, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	origPaths := modsecLogPaths
	modsecLogPaths = []string{"/nonexistent/path", fakePath, "/another/missing"}
	defer func() { modsecLogPaths = origPaths }()

	cfg := &config.Config{}
	got := discoverModSecLogPath(cfg)
	if got != fakePath {
		t.Errorf("want %q, got %q", fakePath, got)
	}
}

func TestDiscoverModSecLogPath_NoneFound(t *testing.T) {
	origPaths := modsecLogPaths
	modsecLogPaths = []string{"/nonexistent/a", "/nonexistent/b"}
	defer func() { modsecLogPaths = origPaths }()

	cfg := &config.Config{}
	got := discoverModSecLogPath(cfg)
	if got != "" {
		t.Errorf("want empty, got %q", got)
	}
}
