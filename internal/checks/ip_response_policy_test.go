package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestIPResponseAnswersFinding(t *testing.T) {
	cfg := &config.Config{}
	scannerBlocks := &config.Config{}
	scannerBlocks.AutoResponse.HTTPScannerAction = "block"

	tests := []struct {
		name    string
		cfg     *config.Config
		finding alert.Finding
		blocked bool
		want    bool
	}{
		{"blocked ftp auth failure", cfg, alert.Finding{Check: "ftp_auth_failure_realtime", Severity: alert.High}, true, true},
		{"challenged ftp auth failure", cfg, alert.Finding{Check: "ftp_auth_failure_realtime", Severity: alert.High}, false, false},
		{"challenged scanner", cfg, alert.Finding{Check: "http_scanner_profile", Severity: alert.High}, false, true},
		{"challenged scanner under block action", scannerBlocks, alert.Finding{Check: "http_scanner_profile", Severity: alert.High}, false, false},
		{"blocked ua spoof", cfg, alert.Finding{Check: "http_ua_spoof", Severity: alert.Critical}, true, true},
		{"challenged ua spoof", cfg, alert.Finding{Check: "http_ua_spoof", Severity: alert.Critical}, false, false},
		{"challenged wp brute force", cfg, alert.Finding{Check: "wp_login_bruteforce", Severity: alert.Critical}, false, true},
		{"challenged high reputation", cfg, alert.Finding{Check: "ip_reputation", Severity: alert.High}, false, true},
		{"challenged critical reputation", cfg, alert.Finding{Check: "ip_reputation", Severity: alert.Critical}, false, false},
		{"blocked critical reputation", cfg, alert.Finding{Check: "ip_reputation", Severity: alert.Critical}, true, true},
		{"blocked waf attacker", cfg, alert.Finding{Check: "waf_attack_blocked", Severity: alert.High}, true, true},
		// Compromise evidence and audit events still need a human even
		// when their source address is already blocked.
		{"blocked webshell observation", cfg, alert.Finding{Check: "php_shield_webshell", Severity: alert.Critical}, true, false},
		{"blocked cpanel login", cfg, alert.Finding{Check: "cpanel_login", Severity: alert.Warning}, true, false},
		{"blocked ftp login", cfg, alert.Finding{Check: "ftp_login_realtime", Severity: alert.Warning}, true, false},
		{"blocked unknown check", cfg, alert.Finding{Check: "not_a_registered_check", Severity: alert.High}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IPResponseAnswersFinding(tt.cfg, tt.finding, tt.blocked); got != tt.want {
				t.Fatalf("IPResponseAnswersFinding(%s, blocked=%v) = %v, want %v", tt.finding.Check, tt.blocked, got, tt.want)
			}
		})
	}
}
