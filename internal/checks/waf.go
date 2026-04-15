package checks

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// CheckWAFStatus verifies that ModSecurity is loaded, the engine is in
// enforcement mode (not DetectionOnly), OWASP/Comodo rules are active,
// and rules are up to date.
func CheckWAFStatus(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	info := platform.Detect()

	// If there is no web server at all, WAF concerns don't apply to this host.
	if info.WebServer == platform.WSNone {
		return findings
	}

	modsecActive := modsecDetected(info)

	if !modsecActive {
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "waf_status",
			Message:  "ModSecurity WAF is not active",
			Details:  wafInstallHint(info),
		})
		return findings // no point checking further
	}

	// --- Engine mode check ---
	engineMode := checkEngineMode(info)
	if engineMode == "detectiononly" {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "waf_detection_only",
			Message:  "ModSecurity is in DetectionOnly mode - attacks are logged but NOT blocked",
			Details:  "SecRuleEngine is set to DetectionOnly. Change to 'On' for enforcement:\nWHM > Security Center > ModSecurity > Edit Global Directive",
		})
	}

	// --- Rule vendor check ---
	// cPanel-only: whmapi1 vendors. Plain hosts rely on file-system probing.
	hasRules := false
	if info.IsCPanel() {
		out, _ := runCmd("whmapi1", "modsec_get_vendors")
		if out != nil {
			outStr := string(out)
			if strings.Contains(outStr, "comodo") || strings.Contains(outStr, "owasp") ||
				strings.Contains(outStr, "OWASP") || strings.Contains(outStr, "Comodo") {
				hasRules = true
			}
		}
	}

	ruleDirs := modsecRuleDirs(info)
	if hasRuleArtifacts(ruleDirs) {
		hasRules = true
	}

	if !hasRules {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "waf_rules",
			Message:  "ModSecurity has no WAF rules loaded",
			Details:  wafRulesHint(info),
		})
	}

	// --- Rule age check + auto-update ---
	if hasRules {
		staleAge := checkRuleAge(ruleDirs)
		if staleAge > 0 {
			// Attempt auto-update before alerting
			updated := false
			if info.IsCPanel() {
				updated = autoUpdateWAFRules()
			}
			if updated {
				// Re-check age after update
				staleAge = checkRuleAge(ruleDirs)
			}
			if staleAge > 0 {
				findings = append(findings, alert.Finding{
					Severity: alert.Warning,
					Check:    "waf_rules_stale",
					Message:  fmt.Sprintf("ModSecurity rules are %d days old - update recommended", staleAge),
					Details:  wafRulesStaleHint(info),
				})
			}
		}
	}

	// --- Virtual patch deployment ---
	// Only cPanel has the modsec user config dirs we write into.
	if info.IsCPanel() {
		deployVirtualPatches()
	}

	// --- Per-account WAF bypass check ---
	// whmapi1-only, skip on non-cPanel hosts.
	if info.IsCPanel() {
		bypassed := checkPerAccountBypass()
		for _, domain := range bypassed {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "waf_bypass",
				Message:  fmt.Sprintf("ModSecurity disabled for domain: %s", domain),
				Details:  "This domain has ModSecurity bypassed. All web attacks pass through unfiltered.\nCheck: WHM > Security Center > ModSecurity > Domains",
			})
		}
	}

	return findings
}

// modsecDetected returns true if a ModSecurity module is loaded for the
// detected web server. It first consults the platform layer, then falls
// back to scanning config files.
func modsecDetected(info platform.Info) bool {
	// cPanel fast path
	if info.IsCPanel() {
		if out, _ := runCmd("whmapi1", "modsec_is_installed"); out != nil &&
			strings.Contains(string(out), "installed: 1") {
			return true
		}
	}

	// Generic file-based probes per web server
	for _, conf := range expandPathGlobs(modsecActivationCandidates(info)) {
		data, err := osFS.ReadFile(conf)
		if err != nil {
			continue
		}
		if modsecEnabledInConfig(info, string(data)) {
			return true
		}
	}
	return false
}

// modsecActivationCandidates returns the config files that can enable the
// ModSecurity module for the detected web server.
func modsecActivationCandidates(info platform.Info) []string {
	var paths []string
	switch info.WebServer {
	case platform.WSApache:
		if info.ApacheConfigDir != "" {
			paths = append(paths,
				filepath.Join(info.ApacheConfigDir, "httpd.conf"),
				filepath.Join(info.ApacheConfigDir, "apache2.conf"),
				filepath.Join(info.ApacheConfigDir, "modsec2.conf"),
				filepath.Join(info.ApacheConfigDir, "conf.d", "modsec2.conf"),
				filepath.Join(info.ApacheConfigDir, "mods-enabled", "security2.conf"),
				filepath.Join(info.ApacheConfigDir, "conf-enabled", "security2.conf"),
				filepath.Join(info.ApacheConfigDir, "conf.d", "mod_security.conf"),
				filepath.Join(info.ApacheConfigDir, "conf.modules.d", "10-mod_security.conf"),
				filepath.Join(info.ApacheConfigDir, "conf.d", "*.conf"),
				filepath.Join(info.ApacheConfigDir, "mods-enabled", "*.conf"),
				filepath.Join(info.ApacheConfigDir, "conf-enabled", "*.conf"),
			)
		}
	case platform.WSNginx:
		if info.NginxConfigDir != "" {
			paths = append(paths,
				filepath.Join(info.NginxConfigDir, "nginx.conf"),
				filepath.Join(info.NginxConfigDir, "conf.d", "*.conf"),
				filepath.Join(info.NginxConfigDir, "sites-enabled", "*"),
			)
		}
	case platform.WSLiteSpeed:
		paths = append(paths,
			"/usr/local/lsws/conf/httpd_config.xml",
		)
	}
	return paths
}

// modsecConfigCandidates returns the set of config files worth scanning
// for ModSecurity directives on the detected web server.
func modsecConfigCandidates(info platform.Info) []string {
	paths := append([]string(nil), modsecActivationCandidates(info)...)
	switch info.WebServer {
	case platform.WSNginx:
		if info.NginxConfigDir != "" {
			paths = append(paths,
				filepath.Join(info.NginxConfigDir, "modules-enabled", "*.conf"),
				filepath.Join(info.NginxConfigDir, "modsec", "main.conf"),
			)
		}
	case platform.WSLiteSpeed:
		paths = append(paths, "/usr/local/lsws/conf/modsec2.conf")
	}
	return paths
}

func modsecEnabledInConfig(info platform.Info, contents string) bool {
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineLower := strings.ToLower(line)
		switch info.WebServer {
		case platform.WSNginx:
			if strings.HasPrefix(lineLower, "#") {
				continue
			}
			if strings.HasPrefix(lineLower, "modsecurity on") ||
				strings.HasPrefix(lineLower, "modsecurity_rules ") ||
				strings.HasPrefix(lineLower, "modsecurity_rules_file ") {
				return true
			}
		case platform.WSLiteSpeed:
			if strings.Contains(lineLower, "mod_security") || strings.Contains(lineLower, "modsecurity") {
				return true
			}
		default:
			if strings.HasPrefix(lineLower, "#") {
				continue
			}
			if strings.Contains(lineLower, "security2_module") ||
				strings.HasPrefix(lineLower, "secruleengine ") ||
				strings.Contains(lineLower, "mod_security2") {
				return true
			}
		}
	}
	return false
}

func expandPathGlobs(paths []string) []string {
	var expanded []string
	seen := make(map[string]struct{})
	for _, candidate := range paths {
		matches := []string{candidate}
		if strings.ContainsAny(candidate, "*?[") {
			if globbed, err := osFS.Glob(candidate); err == nil && len(globbed) > 0 {
				matches = globbed
			}
		}
		for _, match := range matches {
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			expanded = append(expanded, match)
		}
	}
	return expanded
}

// modsecRuleDirs returns the candidate directories where vendor rules live
// for the detected web server/panel combination.
func modsecRuleDirs(info platform.Info) []string {
	var dirs []string
	switch info.WebServer {
	case platform.WSApache:
		if info.IsDebianFamily() {
			dirs = append(dirs,
				"/etc/apache2/conf.d/modsec_vendor_configs/",
				"/etc/modsecurity/",
				"/usr/share/modsecurity-crs/rules/",
			)
		}
		if info.IsRHELFamily() {
			dirs = append(dirs,
				"/etc/httpd/modsecurity.d/",
				"/etc/httpd/modsecurity.d/activated_rules/",
				"/usr/share/modsecurity-crs/rules/",
			)
		}
		dirs = append(dirs, "/usr/local/apache/conf/modsec_vendor_configs/")
	case platform.WSNginx:
		dirs = append(dirs,
			"/etc/nginx/modsec/",
			"/etc/modsecurity/",
			"/usr/share/modsecurity-crs/rules/",
		)
	}
	return dirs
}

// wafInstallHint returns platform-specific install instructions.
func wafInstallHint(info platform.Info) string {
	switch {
	case info.IsCPanel():
		return "No ModSecurity module detected. Install: WHM > Security Center > ModSecurity"
	case info.WebServer == platform.WSNginx && info.IsDebianFamily():
		return "No ModSecurity module detected for Nginx.\nInstall: apt install libnginx-mod-http-modsecurity modsecurity-crs"
	case info.WebServer == platform.WSApache && info.IsDebianFamily():
		return "No ModSecurity module detected for Apache.\nInstall: apt install libapache2-mod-security2 modsecurity-crs && a2enmod security2"
	case info.WebServer == platform.WSApache && info.IsRHELFamily():
		return "No ModSecurity module detected for Apache.\nInstall (requires EPEL): dnf install -y epel-release && dnf install -y mod_security mod_security_crs && systemctl restart httpd"
	case info.WebServer == platform.WSNginx && info.IsRHELFamily():
		return "No ModSecurity module detected for Nginx.\nInstall (requires EPEL): dnf install -y epel-release && dnf install -y nginx-mod-http-modsecurity && systemctl restart nginx"
	}
	return "No ModSecurity module detected. The server has no web application firewall protecting against SQL injection, XSS, and other web attacks."
}

// wafRulesHint returns platform-specific rules-install instructions.
func wafRulesHint(info platform.Info) string {
	if info.IsCPanel() {
		return "ModSecurity is installed but has no OWASP or Comodo rules. Add rules: WHM > Security Center > ModSecurity Vendors"
	}
	if info.IsDebianFamily() {
		return "ModSecurity is installed but has no rules loaded. Install OWASP CRS: apt install modsecurity-crs"
	}
	if info.IsRHELFamily() {
		return "ModSecurity is installed but has no rules loaded. Install OWASP CRS: dnf install --enablerepo=epel modsecurity-crs"
	}
	return "ModSecurity is installed but has no rules loaded."
}

// wafRulesStaleHint returns platform-specific advice for updating stale
// ModSecurity vendor rules.
func wafRulesStaleHint(info platform.Info) string {
	if info.IsCPanel() {
		return "Vendor rules should be updated at least monthly. Check: WHM > Security Center > ModSecurity Vendors > Update"
	}
	if info.IsDebianFamily() {
		return "Vendor rules should be updated at least monthly. Update with: apt update && apt upgrade modsecurity-crs"
	}
	if info.IsRHELFamily() {
		return "Vendor rules should be updated at least monthly. Update with: dnf upgrade modsecurity-crs"
	}
	return "Vendor rules should be updated at least monthly."
}

// checkEngineMode reads ModSecurity config files to determine the SecRuleEngine setting.
// Returns "on", "detectiononly", "off", or "" if unknown.
func checkEngineMode(info platform.Info) string {
	configPaths := modsecConfigCandidates(info)
	// Also include the top-level modsecurity.conf installed by distro packages.
	configPaths = append(configPaths,
		"/etc/modsecurity/modsecurity.conf",
		"/etc/nginx/modsec/modsecurity.conf",
	)

	for _, path := range configPaths {
		f, err := osFS.Open(path)
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
	oldestMtime, found := oldestRuleArtifact(ruleDirs)
	if !found {
		return 0
	}

	age := int(time.Since(oldestMtime).Hours() / 24)
	if age > 30 {
		return age
	}
	return 0
}

func hasRuleArtifacts(ruleDirs []string) bool {
	_, found := oldestRuleArtifact(ruleDirs)
	return found
}

func oldestRuleArtifact(ruleDirs []string) (time.Time, bool) {
	var oldestMtime time.Time
	found := false

	for _, dir := range ruleDirs {
		entries, err := osFS.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				// Rule file directly in the rule dir (distro CRS layout,
				// e.g. /usr/share/modsecurity-crs/rules/REQUEST-*.conf).
				info, err := entry.Info()
				if err != nil {
					continue
				}
				if !isRuleArtifact(entry.Name()) {
					continue
				}
				if !found || info.ModTime().Before(oldestMtime) {
					oldestMtime = info.ModTime()
					found = true
				}
				continue
			}
			// Subdirectory: scan one level deeper for vendor-packed rules
			// (cPanel layout, e.g. /usr/local/apache/conf/modsec_vendor_configs/OWASP/*.conf).
			subDir := dir + "/" + entry.Name()
			subEntries, err := osFS.ReadDir(subDir)
			if err != nil {
				continue
			}
			for _, subEntry := range subEntries {
				if subEntry.IsDir() {
					continue
				}
				if !isRuleArtifact(subEntry.Name()) {
					continue
				}
				info, err := subEntry.Info()
				if err != nil {
					continue
				}
				if !found || info.ModTime().Before(oldestMtime) {
					oldestMtime = info.ModTime()
					found = true
				}
			}
		}
	}

	return oldestMtime, found
}

// isRuleArtifact reports whether a filename looks like a ModSecurity rule
// or data artifact (.conf, .data, .rules) so unrelated files like README
// or LICENSE don't dominate the oldest-mtime calculation.
func isRuleArtifact(name string) bool {
	name = strings.ToLower(name)
	return strings.HasSuffix(name, ".conf") ||
		strings.HasSuffix(name, ".data") ||
		strings.HasSuffix(name, ".rules")
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
	srcData, err := osFS.ReadFile(srcPath)
	if err != nil {
		return // no custom rules to deploy
	}

	for _, dest := range destPaths {
		dir := filepath.Dir(dest)
		if _, err := osFS.Stat(dir); os.IsNotExist(err) {
			continue
		}

		// Check if CSM rules are already included
		existing, err := osFS.ReadFile(dest)
		if err == nil && strings.Contains(string(existing), "CSM Custom ModSecurity Rules") {
			// Already deployed - check if rules need updating
			if string(existing) == string(srcData) {
				return // up to date
			}
		}

		// Deploy: if file exists and has non-CSM content, append. Otherwise write.
		if err == nil && len(existing) > 0 && !strings.Contains(string(existing), "CSM Custom ModSecurity Rules") {
			// Append to existing user config
			// #nosec G302 G304 -- WAF rule file read by Apache/nginx as a different user; dest is fixed list above.
			f, err := os.OpenFile(dest, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				continue
			}
			_, _ = f.Write([]byte("\n\n"))
			_, _ = f.Write(srcData)
			_ = f.Close()
		} else {
			// Write or overwrite
			// #nosec G306 -- same reason: webserver-readable WAF rule file.
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
func CheckModSecAuditLog(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	logPaths := platform.Detect().ModSecAuditLogPaths
	if len(logPaths) == 0 {
		return nil
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
