//go:build linux

package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
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
	if f.Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical (CSM custom rule)", f.Severity)
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
