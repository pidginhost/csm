package checks

import (
	"fmt"
	"os"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// CheckWAFStatus verifies that ModSecurity is loaded and OWASP/Comodo
// rules are active. Alerts if the WAF is disabled or rules are missing.
func CheckWAFStatus(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Check if ModSecurity module is loaded in LiteSpeed/Apache
	modsecActive := false

	// Check LiteSpeed modsec
	lsConf := "/usr/local/lsws/conf/httpd_config.xml"
	if data, err := os.ReadFile(lsConf); err == nil {
		if strings.Contains(string(data), "mod_security") || strings.Contains(string(data), "modsecurity") {
			modsecActive = true
		}
	}

	// Check Apache modsec
	apacheConfs := []string{
		"/etc/apache2/conf.d/modsec2.conf",
		"/etc/apache2/conf/httpd.conf",
		"/usr/local/apache/conf/httpd.conf",
	}
	for _, conf := range apacheConfs {
		if data, err := os.ReadFile(conf); err == nil {
			if strings.Contains(string(data), "mod_security2") || strings.Contains(string(data), "SecRuleEngine") {
				modsecActive = true
			}
		}
	}

	// Check cPanel ModSecurity status
	out, _ := runCmd("whmapi1", "modsec_is_installed")
	if out != nil && strings.Contains(string(out), "installed: 1") {
		modsecActive = true
	}

	if !modsecActive {
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "waf_status",
			Message:  "ModSecurity WAF is not active",
			Details:  "No ModSecurity module detected. The server has no web application firewall protecting against SQL injection, XSS, and other web attacks.\nInstall: WHM > Security Center > ModSecurity",
		})
	}

	// Check if OWASP/Comodo rules are loaded
	if modsecActive {
		hasRules := false

		// Check for vendor rules
		out, _ := runCmd("whmapi1", "modsec_get_vendors")
		if out != nil {
			outStr := string(out)
			if strings.Contains(outStr, "comodo") || strings.Contains(outStr, "owasp") ||
				strings.Contains(outStr, "OWASP") || strings.Contains(outStr, "Comodo") {
				hasRules = true
			}
		}

		// Check rule files exist
		rulePaths := []string{
			"/etc/apache2/conf.d/modsec_vendor_configs/",
			"/usr/local/apache/conf/modsec_vendor_configs/",
		}
		for _, rp := range rulePaths {
			if entries, err := os.ReadDir(rp); err == nil && len(entries) > 0 {
				hasRules = true
			}
		}

		if !hasRules {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "waf_rules",
				Message:  "ModSecurity has no WAF rules loaded",
				Details:  "ModSecurity is installed but has no OWASP or Comodo rules. Add rules: WHM > Security Center > ModSecurity Vendors",
			})
		}
	}

	return findings
}

// CheckModSecAuditLog parses the ModSecurity audit log for blocked attacks.
// This gives visibility into what the WAF is actually catching.
func CheckModSecAuditLog(_ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	logPaths := []string{
		"/var/log/apache2/modsec_audit.log",
		"/usr/local/apache/logs/modsec_audit.log",
		"/var/log/modsec_audit.log",
	}

	var lines []string
	for _, path := range logPaths {
		lines = tailFile(path, 100)
		if len(lines) > 0 {
			break
		}
	}
	if len(lines) == 0 {
		return nil
	}

	// Count blocked attacks per IP
	blocked := make(map[string]int)
	for _, line := range lines {
		// ModSec audit log format varies, look for common patterns
		if strings.Contains(line, "403") || strings.Contains(line, "Access denied") {
			ip := extractIPFromLog(line)
			if ip != "" {
				blocked[ip]++
			}
		}
	}

	// Alert on high-volume attackers
	for ip, count := range blocked {
		if count >= 20 {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "waf_attack_blocked",
				Message:  fmt.Sprintf("WAF blocking high-volume attacker: %s (%d blocked requests)", ip, count),
				Details:  "Consider permanent CSF block if persistent",
			})
		}
	}

	return findings
}
