package checks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// wafRulesAssembleRetryDelay is the wait between the first negative
// probe and the re-probe on cPanel+LiteSpeed hosts where cPanel's
// nightly modsec_assemble briefly leaves both `whmapi1
// modsec_get_vendors` and the vendor dir empty while it rewrites the
// tree in place. Observed windows are <10s; 30s gives margin without
// meaningfully delaying the surrounding deep-scan tier. Tests override
// this to keep the suite fast.
var wafRulesAssembleRetryDelay = 30 * time.Second

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
	ruleDirs := modsecRuleDirs(info)
	hasRules := probeWAFRules(info, ruleDirs)

	// cPanel+LiteSpeed: cPanel's nightly modsec_assemble rewrites the
	// vendor tree in place, so for ~6-10s both `whmapi1
	// modsec_get_vendors` and the vendor dir return empty. A production
	// false positive at 01:10:27 fired 6s after the rewrite. Re-probe
	// once after a short delay before alerting; on a host that really
	// has no rules, the re-probe is still negative and we alert in the
	// same scan, so this doesn't shift detection to the next deep tier.
	if !hasRules && info.IsCPanel() && info.WebServer == platform.WSLiteSpeed {
		select {
		case <-time.After(wafRulesAssembleRetryDelay):
		case <-ctx.Done():
			return findings
		}
		hasRules = probeWAFRules(info, ruleDirs)
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

// probeWAFRules checks whether any WAF rule source — cPanel's whmapi1
// vendor list or the on-disk vendor/CRS directories — currently
// reports rules. Used by CheckWAFStatus directly and again on retry
// for the cPanel+LiteSpeed modsec_assemble race.
func probeWAFRules(info platform.Info, ruleDirs []string) bool {
	if info.IsCPanel() {
		if out, _ := runCmd("whmapi1", "modsec_get_vendors"); out != nil {
			outStr := string(out)
			if strings.Contains(outStr, "comodo") || strings.Contains(outStr, "owasp") ||
				strings.Contains(outStr, "OWASP") || strings.Contains(outStr, "Comodo") {
				return true
			}
		}
	}
	return hasRuleArtifacts(ruleDirs)
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

// modsecRuleDirs delegates to the canonical helper in internal/modsec.
// Kept as a package-local thin wrapper because the existing waf check tests
// reference this name directly.
func modsecRuleDirs(info platform.Info) []string {
	return modsec.RuleDirs(info)
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

// Markers delimiting the CSM-managed section inside modsec2.user.conf.
// That file is shared with operator-maintained rules (Host-scoped
// ctl:ruleRemoveById exclusions and the like), so CSM may only ever
// rewrite the bytes between these two lines. vpLegacyMarker is the header
// comment of the rules file itself, which is all that pre-delimiter CSM
// versions wrote; it locates those deployments for upgrade.
const (
	vpBeginMarker            = "# BEGIN CSM Custom ModSecurity Rules (managed by CSM - do not edit inside this block)"
	vpEndMarker              = "# END CSM Custom ModSecurity Rules"
	vpLegacyMarker           = "# CSM Custom ModSecurity Rules"
	vpOverridesIncludeMarker = "# CSM overrides - managed by CSM rule management"
)

// deployVirtualPatches ensures CSM's custom ModSec rules are installed.
// These provide virtual patches for known WordPress CVEs.
//
// The destination is shared with operator rules, so CSM only ever creates
// or rewrites its own marker-delimited section; every byte outside the
// section is preserved verbatim.
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
	section := buildVPSection(srcData)

	for _, dest := range destPaths {
		dir := filepath.Dir(dest)
		if _, err := osFS.Stat(dir); os.IsNotExist(err) {
			continue
		}

		existing, err := osFS.ReadFile(dest)
		if err != nil && !os.IsNotExist(err) {
			// Present but unreadable: rewriting blind could destroy
			// operator rules, so leave this candidate alone.
			continue
		}

		merged, upToDate := mergeVPSection(existing, section)
		if upToDate {
			return
		}

		// #nosec G306 -- WAF rule file read by Apache/nginx as a different user.
		if err := osFS.WriteFile(dest, merged, 0644); err != nil {
			continue
		}

		fmt.Fprintf(os.Stderr, "[%s] Virtual patches deployed to %s\n",
			time.Now().Format("2006-01-02 15:04:05"), dest)
		return
	}
}

// MergeModSecUserConfSection merges CSM's ModSecurity rules payload into
// the current contents of a modsec2.user.conf, confining CSM to its
// marker-delimited section so operator-maintained rules outside the
// section survive every deploy. It is exported because three call sites
// write this file (the WAF check cycle here, `csm install`, and the
// daemon startup config deploy); routing them all through one merge
// guarantees no caller ever whole-file-overwrites operator rules.
//
// existing is the current file contents (nil for a missing file). merged
// is only meaningful when changed is true; changed=false means the file
// already carries the wanted section and must not be rewritten.
func MergeModSecUserConfSection(existing, srcData []byte) (merged []byte, changed bool) {
	merged, upToDate := mergeVPSection(existing, buildVPSection(srcData))
	return merged, !upToDate
}

// buildVPSection wraps the rules payload in the begin/end marker lines.
// The result is deterministic for a given payload so later cycles can
// recognize an up-to-date section by byte comparison.
func buildVPSection(srcData []byte) []byte {
	section := make([]byte, 0, len(vpBeginMarker)+len(srcData)+len(vpEndMarker)+3)
	section = append(section, vpBeginMarker...)
	section = append(section, '\n')
	section = append(section, srcData...)
	if len(srcData) > 0 && srcData[len(srcData)-1] != '\n' {
		section = append(section, '\n')
	}
	section = append(section, vpEndMarker...)
	section = append(section, '\n')
	return section
}

// mergeVPSection computes the new content for a modsec user conf so that
// it carries exactly one copy of the CSM section while every byte outside
// the section stays untouched. upToDate reports that the file already
// holds the wanted section and no write is needed.
func mergeVPSection(existing, section []byte) (merged []byte, upToDate bool) {
	if len(existing) == 0 {
		return section, false
	}

	if begin, _, ok := markerLineBounds(existing, vpBeginMarker); ok {
		if end := vpSectionEnd(existing[begin:]); end >= 0 {
			if bytes.Equal(existing[begin:begin+end], section) {
				return nil, true
			}
			merged = append(merged, existing[:begin]...)
			merged = append(merged, section...)
			merged = append(merged, existing[begin+end:]...)
			return merged, false
		}

		// A begin marker without an end marker is a malformed CSM block.
		// Replace from the exact begin line so the next cycle is delimited
		// again instead of falling through to the legacy header inside it.
		blockEnd := vpBlockEndBeforePreservedTail(existing, begin)
		merged = append(merged, existing[:begin]...)
		merged = append(merged, section...)
		merged = append(merged, existing[blockEnd:]...)
		return merged, false
	}

	if legacy, _, ok := markerLineBounds(existing, vpLegacyMarker); ok {
		// Pre-delimiter CSM versions appended the raw rules file, so the
		// CSM content starts at this exact header line. Installer and
		// daemon deploys appended the overrides Include after the raw
		// rules, so preserve that tail when it is present.
		legacyEnd := vpBlockEndBeforePreservedTail(existing, legacy)
		merged = append(merged, existing[:legacy]...)
		merged = append(merged, section...)
		merged = append(merged, existing[legacyEnd:]...)
		return merged, false
	}

	// Operator-only file: append the section, separated by one blank
	// line, keeping the existing bytes exactly as they are.
	merged = append(merged, existing...)
	if existing[len(existing)-1] != '\n' {
		merged = append(merged, '\n')
	}
	merged = append(merged, '\n')
	merged = append(merged, section...)
	return merged, false
}

func vpBlockEndBeforePreservedTail(existing []byte, blockStart int) int {
	blockEnd := len(existing)
	if tail, _, ok := markerLineBounds(existing[blockStart:], vpOverridesIncludeMarker); ok && tail > 0 {
		blockEnd = blockStart + tail
		if existing[blockEnd-1] == '\n' {
			blockEnd--
		}
	}
	return blockEnd
}

// markerLineBounds returns the start offset and end offset (including the
// trailing newline when present) for an exact marker line. Matching the
// whole line keeps operator comments that merely mention marker text from
// being treated as CSM-owned content.
func markerLineBounds(data []byte, marker string) (start, end int, ok bool) {
	markerBytes := []byte(marker)
	for start < len(data) {
		lineEnd := bytes.IndexByte(data[start:], '\n')
		end = len(data)
		next := len(data)
		if lineEnd >= 0 {
			end = start + lineEnd
			next = end + 1
		}
		line := data[start:end]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if bytes.Equal(line, markerBytes) {
			return start, next, true
		}
		start = next
	}
	return 0, 0, false
}

// vpSectionEnd returns the offset just past the end-marker line (its
// trailing newline included when present), or -1 when there is no end
// marker. data must start at the section's begin line.
func vpSectionEnd(data []byte) int {
	if _, end, ok := markerLineBounds(data, vpEndMarker); ok {
		return end
	}
	return -1
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
				SourceIP: ip,
				Message:  fmt.Sprintf("WAF blocking high-volume attacker: %s (%d blocked requests)", ip, count),
				Details:  fmt.Sprintf("IP %s has been blocked %d times by ModSecurity. Consider permanent block via CSM.", ip, count),
			})
		}
	}

	return findings
}
