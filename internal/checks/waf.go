package checks

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// CheckWAFStatus verifies that ModSecurity is loaded, the engine is in
// enforcement mode (not DetectionOnly), OWASP/Comodo rules are active,
// and rules are up to date.
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
		return findings // no point checking further
	}

	// --- Engine mode check ---
	engineMode := checkEngineMode()
	if engineMode == "detectiononly" {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "waf_detection_only",
			Message:  "ModSecurity is in DetectionOnly mode — attacks are logged but NOT blocked",
			Details:  "SecRuleEngine is set to DetectionOnly. Change to 'On' for enforcement:\nWHM > Security Center > ModSecurity > Edit Global Directive",
		})
	}

	// --- Rule vendor check ---
	hasRules := false
	out, _ = runCmd("whmapi1", "modsec_get_vendors")
	if out != nil {
		outStr := string(out)
		if strings.Contains(outStr, "comodo") || strings.Contains(outStr, "owasp") ||
			strings.Contains(outStr, "OWASP") || strings.Contains(outStr, "Comodo") {
			hasRules = true
		}
	}

	// Check rule files exist
	ruleDirs := []string{
		"/etc/apache2/conf.d/modsec_vendor_configs/",
		"/usr/local/apache/conf/modsec_vendor_configs/",
	}
	for _, rp := range ruleDirs {
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

	// --- Rule age check + auto-update ---
	if hasRules {
		staleAge := checkRuleAge(ruleDirs)
		if staleAge > 0 {
			// Attempt auto-update before alerting
			updated := autoUpdateWAFRules()
			if updated {
				// Re-check age after update
				staleAge = checkRuleAge(ruleDirs)
			}
			if staleAge > 0 {
				findings = append(findings, alert.Finding{
					Severity: alert.Warning,
					Check:    "waf_rules_stale",
					Message:  fmt.Sprintf("ModSecurity rules are %d days old — update recommended", staleAge),
					Details:  "Vendor rules should be updated at least monthly. Check: WHM > Security Center > ModSecurity Vendors > Update",
				})
			}
		}
	}

	// --- Virtual patch deployment ---
	deployVirtualPatches()

	// --- Per-account WAF bypass check ---
	bypassed := checkPerAccountBypass()
	for _, domain := range bypassed {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "waf_bypass",
			Message:  fmt.Sprintf("ModSecurity disabled for domain: %s", domain),
			Details:  "This domain has ModSecurity bypassed. All web attacks pass through unfiltered.\nCheck: WHM > Security Center > ModSecurity > Domains",
		})
	}

	return findings
}

// checkEngineMode reads ModSecurity config files to determine the SecRuleEngine setting.
// Returns "on", "detectiononly", "off", or "" if unknown.
func checkEngineMode() string {
	configPaths := []string{
		"/etc/apache2/conf.d/modsec2.conf",
		"/etc/apache2/conf.d/modsec/modsec2.cpanel.conf",
		"/usr/local/apache/conf/modsec2.conf",
		"/usr/local/lsws/conf/modsec2.conf",
	}

	for _, path := range configPaths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") {
				continue
			}
			lineLower := strings.ToLower(line)
			if strings.HasPrefix(lineLower, "secruleengine") {
				parts := strings.Fields(lineLower)
				if len(parts) >= 2 {
					_ = f.Close()
					return parts[1]
				}
			}
		}
		_ = f.Close()
	}
	return ""
}

// checkRuleAge returns the age in days of the oldest rule file, or 0 if rules are fresh.
// Only alerts if rules are >30 days old.
func checkRuleAge(ruleDirs []string) int {
	var oldestMtime time.Time

	for _, dir := range ruleDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				// Check files inside vendor subdirectories
				subDir := dir + "/" + entry.Name()
				subEntries, err := os.ReadDir(subDir)
				if err != nil {
					continue
				}
				for _, subEntry := range subEntries {
					if subEntry.IsDir() {
						continue
					}
					info, err := subEntry.Info()
					if err != nil {
						continue
					}
					if oldestMtime.IsZero() || info.ModTime().Before(oldestMtime) {
						oldestMtime = info.ModTime()
					}
				}
			}
		}
	}

	if oldestMtime.IsZero() {
		return 0
	}

	age := int(time.Since(oldestMtime).Hours() / 24)
	if age > 30 {
		return age
	}
	return 0
}

// checkPerAccountBypass checks for domains with ModSecurity disabled.
func checkPerAccountBypass() []string {
	out, err := runCmd("whmapi1", "modsec_get_rules")
	if err != nil || out == nil {
		return nil
	}

	var bypassed []string
	outStr := string(out)

	// Parse YAML-like output for disabled domains
	// The output format varies, but disabled rules/domains show "disabled: 1" or "active: 0"
	lines := strings.Split(outStr, "\n")
	for i, line := range lines {
		lineLower := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(lineLower, "disabled: 1") || strings.Contains(lineLower, "active: 0") {
			// Look backward for the domain/config name
			for j := i - 1; j >= 0 && j >= i-5; j-- {
				prev := strings.TrimSpace(lines[j])
				if strings.HasSuffix(prev, ":") && !strings.HasPrefix(prev, "-") {
					domain := strings.TrimSuffix(prev, ":")
					if strings.Contains(domain, ".") { // looks like a domain
						bypassed = append(bypassed, domain)
					}
					break
				}
			}
		}
	}

	return bypassed
}

// deployVirtualPatches ensures CSM's custom ModSec rules are installed.
// These provide virtual patches for known WordPress CVEs.
func deployVirtualPatches() {
	// Possible modsec user config paths
	destPaths := []string{
		"/etc/apache2/conf.d/modsec/modsec2.user.conf",
		"/usr/local/apache/conf/modsec2.user.conf",
	}

	srcPath := "/opt/csm/configs/csm_modsec_custom.conf"
	srcData, err := os.ReadFile(srcPath)
	if err != nil {
		return // no custom rules to deploy
	}

	for _, dest := range destPaths {
		dir := filepath.Dir(dest)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		// Check if CSM rules are already included
		existing, err := os.ReadFile(dest)
		if err == nil && strings.Contains(string(existing), "CSM Custom ModSecurity Rules") {
			// Already deployed — check if rules need updating
			if string(existing) == string(srcData) {
				return // up to date
			}
		}

		// Deploy: if file exists and has non-CSM content, append. Otherwise write.
		if err == nil && len(existing) > 0 && !strings.Contains(string(existing), "CSM Custom ModSecurity Rules") {
			// Append to existing user config
			f, err := os.OpenFile(dest, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				continue
			}
			_, _ = f.Write([]byte("\n\n"))
			_, _ = f.Write(srcData)
			_ = f.Close()
		} else {
			// Write or overwrite
			_ = os.WriteFile(dest, srcData, 0644)
		}

		fmt.Fprintf(os.Stderr, "[%s] Virtual patches deployed to %s\n",
			time.Now().Format("2006-01-02 15:04:05"), dest)
		return
	}
}

// autoUpdateWAFRules triggers ModSecurity vendor rule updates via whmapi1.
// Returns true if an update was successfully triggered.
func autoUpdateWAFRules() bool {
	// Get installed vendors
	out, err := runCmd("whmapi1", "modsec_get_vendors")
	if err != nil || out == nil {
		return false
	}

	// Parse vendor IDs from output (look for "vendor_id:" lines)
	var vendors []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "vendor_id:") || strings.HasPrefix(line, "id:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				vid := strings.TrimSpace(parts[1])
				if vid != "" {
					vendors = append(vendors, vid)
				}
			}
		}
	}

	if len(vendors) == 0 {
		return false
	}

	// Update each vendor
	updated := false
	for _, vid := range vendors {
		out, err := runCmd("whmapi1", "modsec_update_vendor", fmt.Sprintf("vendor_id=%s", vid))
		if err == nil && out != nil && strings.Contains(string(out), "result: 1") {
			fmt.Fprintf(os.Stderr, "[%s] WAF auto-update: vendor %s updated successfully\n",
				time.Now().Format("2006-01-02 15:04:05"), vid)
			updated = true
		}
	}

	return updated
}

// CheckModSecAuditLog parses the ModSecurity audit log for blocked attacks.
// High-volume attackers are reported for potential auto-blocking.
func CheckModSecAuditLog(cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	logPaths := []string{
		"/var/log/apache2/modsec_audit.log",
		"/usr/local/apache/logs/modsec_audit.log",
		"/var/log/modsec_audit.log",
	}

	var lines []string
	for _, path := range logPaths {
		lines = tailFile(path, 200)
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
		if strings.Contains(line, "403") || strings.Contains(line, "Access denied") ||
			strings.Contains(line, "MODSEC") || strings.Contains(line, "mod_security") {
			ip := extractIPFromLog(line)
			if ip != "" && !isInfraIP(ip, cfg.InfraIPs) {
				blocked[ip]++
			}
		}
	}

	// Alert on high-volume attackers (auto-block integration via check name)
	for ip, count := range blocked {
		if count >= 20 {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "waf_attack_blocked",
				Message:  fmt.Sprintf("WAF blocking high-volume attacker: %s (%d blocked requests)", ip, count),
				Details:  fmt.Sprintf("IP %s has been blocked %d times by ModSecurity. Consider permanent block via CSM.", ip, count),
			})
		}
	}

	return findings
}
