package checks

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// AutoRespondDBMalware processes database injection findings and takes
// automated action: blocks attacker IPs extracted from WordPress session
// tokens, revokes compromised user sessions, and cleans confirmed
// malicious content from wp_options.
//
// Only acts on high-confidence findings:
//   - db_options_injection with confirmed malicious external script URLs
//   - db_siteurl_hijack (siteurl/home pointing to malicious content)
//
// Does NOT act on:
//   - db_spam_injection (spam posts — needs manual review)
//   - db_post_injection (script in posts — too many FPs from page builders)
//   - db_options_injection without confirmed malicious URLs
func AutoRespondDBMalware(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	if !cfg.AutoResponse.Enabled || !cfg.AutoResponse.CleanDatabase {
		return nil
	}

	var actions []alert.Finding

	for _, f := range findings {
		switch f.Check {
		case "db_options_injection":
			acts := handleMaliciousOption(cfg, f)
			actions = append(actions, acts...)
		case "db_siteurl_hijack":
			acts := handleSiteurlHijack(cfg, f)
			actions = append(actions, acts...)
		}
	}

	return actions
}

// handleMaliciousOption checks if a db_options_injection finding contains
// a confirmed malicious external script URL, and if so:
// 1. Extracts attacker IPs from WP sessions and emits block findings
// 2. Revokes sessions for users with non-infra, non-private IPs only
// 3. Backs up and cleans the malicious content from the option
func handleMaliciousOption(cfg *config.Config, f alert.Finding) []alert.Finding {
	var actions []alert.Finding

	dbName, optionName := parseDBFindingDetails(f.Details)
	if dbName == "" || optionName == "" {
		return nil
	}

	// Validate option name — must be a plausible WP option name.
	if !isValidOptionName(optionName) {
		return nil
	}

	// Never act on CSM backup options — they preserve original malicious
	// content for recovery. Acting on them causes cascading backup loops.
	if strings.HasPrefix(optionName, "csm_backup_") {
		return nil
	}

	creds := findCredsForDB(dbName)
	if creds.dbName == "" {
		return nil
	}

	prefix := creds.tablePrefix
	if prefix == "" {
		prefix = "wp_"
	}

	// Re-read the FULL option value from the database — the finding's
	// Details field only has a truncated 200-char preview.
	fullValue := readOptionValue(creds, prefix, optionName)
	if fullValue == "" {
		return nil
	}

	// Only act on options with confirmed malicious external script URLs.
	maliciousURL := extractMaliciousScriptURL(fullValue)
	if maliciousURL == "" {
		return nil
	}

	// 1. Extract and block attacker IPs from active WP sessions.
	suspiciousIPs := extractSuspiciousSessionIPs(creds, prefix, cfg.InfraIPs)
	for _, ip := range suspiciousIPs {
		// Emit as auto_block check so AutoBlockIPs processes it.
		actions = append(actions, alert.Finding{
			Severity:  alert.Critical,
			Check:     "auto_block",
			Message:   fmt.Sprintf("AUTO-BLOCK: %s (active WP session on compromised site, DB: %s)", ip, dbName),
			Timestamp: time.Now(),
		})
	}

	// 2. Revoke sessions only for users with suspicious IPs.
	// This preserves the site admin's session if they're on an infra IP.
	revoked := revokeCompromisedSessions(creds, prefix, cfg.InfraIPs)
	if revoked > 0 {
		actions = append(actions, alert.Finding{
			Severity:  alert.Warning,
			Check:     "auto_response",
			Message:   fmt.Sprintf("AUTO-DB-CLEAN: Revoked %d compromised WordPress sessions (DB: %s)", revoked, dbName),
			Timestamp: time.Now(),
		})
	}

	// 3. Back up the original value, then clean the malicious content.
	cleaned := backupAndCleanOption(creds, prefix, optionName, fullValue, maliciousURL)
	if cleaned {
		actions = append(actions, alert.Finding{
			Severity:  alert.Warning,
			Check:     "auto_response",
			Message:   fmt.Sprintf("AUTO-DB-CLEAN: Removed malicious script from wp_options '%s' (DB: %s, URL: %s)", optionName, dbName, maliciousURL),
			Timestamp: time.Now(),
		})
	}

	return actions
}

// handleSiteurlHijack handles siteurl/home hijacking by revoking sessions
// and blocking attacker IPs. Does NOT modify siteurl/home values.
func handleSiteurlHijack(cfg *config.Config, f alert.Finding) []alert.Finding {
	var actions []alert.Finding

	dbName, _ := parseDBFindingDetails(f.Details)
	if dbName == "" {
		return nil
	}

	creds := findCredsForDB(dbName)
	if creds.dbName == "" {
		return nil
	}

	prefix := creds.tablePrefix
	if prefix == "" {
		prefix = "wp_"
	}

	suspiciousIPs := extractSuspiciousSessionIPs(creds, prefix, cfg.InfraIPs)
	for _, ip := range suspiciousIPs {
		actions = append(actions, alert.Finding{
			Severity:  alert.Critical,
			Check:     "auto_block",
			Message:   fmt.Sprintf("AUTO-BLOCK: %s (active session on hijacked site, DB: %s)", ip, dbName),
			Timestamp: time.Now(),
		})
	}

	revoked := revokeCompromisedSessions(creds, prefix, cfg.InfraIPs)
	if revoked > 0 {
		actions = append(actions, alert.Finding{
			Severity:  alert.Warning,
			Check:     "auto_response",
			Message:   fmt.Sprintf("AUTO-DB-CLEAN: Revoked %d sessions on hijacked site (DB: %s)", revoked, dbName),
			Timestamp: time.Now(),
		})
	}

	return actions
}

// --- URL analysis ---

// scriptSrcRe matches <script src="..."> or <script src=...> patterns.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']?(https?://[^"'\s>]+)`)

// knownSafeDomains are legitimate services that embed scripts in wp_options.
var knownSafeDomains = []string{
	"googletagmanager.com",
	"google-analytics.com",
	"googleapis.com",
	"gstatic.com",
	"google.com",
	"facebook.net",
	"facebook.com",
	"fbcdn.net",
	"connect.facebook.net",
	"chimpstatic.com",
	"mailchimp.com",
	"hotjar.com",
	"clarity.ms",
	"cloudflare.com",
	"cdnjs.cloudflare.com",
	"jquery.com",
	"jsdelivr.net",
	"unpkg.com",
	"wp.com",
	"wordpress.com",
	"gravatar.com",
	"tawk.to",
	"crisp.chat",
	"tidio.co",
	"intercom.io",
	"zendesk.com",
	"hubspot.com",
	"hubspot.net",
	"hs-scripts.com",
	"hs-analytics.net",
	"hsforms.com",
	"mautic.net",
	"pinterest.com",
	"twitter.com",
	"linkedin.com",
	"addthis.com",
	"sharethis.com",
	"recaptcha.net",
	"stripe.com",
	"paypal.com",
	"brevo-mail.com",
}

// extractMaliciousScriptURL finds a <script src="..."> URL in the content
// that is NOT from a known safe domain.
func extractMaliciousScriptURL(content string) string {
	matches := scriptSrcRe.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		url := match[1]
		if !isSafeScriptDomain(url) {
			return url
		}
	}
	return ""
}

// isSafeScriptDomain checks if a script URL is from a known safe domain.
func isSafeScriptDomain(url string) bool {
	urlLower := strings.ToLower(url)
	urlLower = strings.TrimPrefix(urlLower, "https://")
	urlLower = strings.TrimPrefix(urlLower, "http://")
	host := urlLower
	if idx := strings.IndexByte(host, '/'); idx >= 0 {
		host = host[:idx]
	}
	if idx := strings.IndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}

	for _, safe := range knownSafeDomains {
		if host == safe || strings.HasSuffix(host, "."+safe) {
			return true
		}
	}
	return false
}

// --- Validation ---

// validOptionNameRe allows alphanumeric, underscores, hyphens, colons, and dots.
// Rejects anything that could be SQL injection.
var validOptionNameRe = regexp.MustCompile(`^[a-zA-Z0-9_\-:.]+$`)

// isValidOptionName validates that an option name is safe for SQL interpolation.
func isValidOptionName(name string) bool {
	return len(name) > 0 && len(name) <= 191 && validOptionNameRe.MatchString(name)
}

// --- DB helpers ---

// parseDBFindingDetails extracts the database name and option name from
// a finding's Details field.
func parseDBFindingDetails(details string) (dbName, optionName string) {
	for _, line := range strings.Split(details, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Database: ") {
			dbName = strings.TrimPrefix(line, "Database: ")
		}
		if strings.HasPrefix(line, "Option: ") {
			optionName = strings.TrimPrefix(line, "Option: ")
		}
	}
	return
}

// findCredsForDB finds wp-config.php credentials that match a database name.
func findCredsForDB(dbName string) wpDBCreds {
	wpConfigs, _ := osFS.Glob("/home/*/public_html/wp-config.php")
	addonConfigs, _ := osFS.Glob("/home/*/*/wp-config.php")
	wpConfigs = append(wpConfigs, addonConfigs...)

	for _, path := range wpConfigs {
		creds := parseWPConfig(path)
		if creds.dbName == dbName {
			return creds
		}
	}
	return wpDBCreds{}
}

// readOptionValue reads the full value of a wp_option from the database.
func readOptionValue(creds wpDBCreds, prefix, optionName string) string {
	if !isValidOptionName(optionName) {
		return ""
	}
	query := fmt.Sprintf(
		"SELECT option_value FROM %soptions WHERE option_name='%s' LIMIT 1",
		prefix, escapeSQLString(optionName))
	lines := runMySQLQuery(creds, query)
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

// extractSuspiciousSessionIPs reads WP session tokens and returns IPs that
// are NOT infra IPs, not private, and not loopback.
func extractSuspiciousSessionIPs(creds wpDBCreds, prefix string, infraIPs []string) []string {
	query := fmt.Sprintf(
		"SELECT meta_value FROM %susermeta WHERE meta_key='session_tokens' AND meta_value != ''",
		prefix)
	lines := runMySQLQuery(creds, query)

	seen := make(map[string]bool)
	var ips []string

	ipRe := regexp.MustCompile(`"ip";s:\d+:"([^"]+)"`)

	for _, line := range lines {
		matches := ipRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			ip := m[1]
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() {
				continue
			}
			if isInfraIP(ip, infraIPs) {
				continue
			}
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}

	return ips
}

// revokeCompromisedSessions clears session_tokens only for WP users whose
// sessions contain non-infra, non-private IPs. Returns count of users revoked.
func revokeCompromisedSessions(creds wpDBCreds, prefix string, infraIPs []string) int {
	// Get user IDs with active sessions.
	query := fmt.Sprintf(
		"SELECT user_id, meta_value FROM %susermeta WHERE meta_key='session_tokens' AND meta_value != ''",
		prefix)
	lines := runMySQLQuery(creds, query)

	ipRe := regexp.MustCompile(`"ip";s:\d+:"([^"]+)"`)
	revoked := 0

	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		userID := strings.TrimSpace(parts[0])
		sessionData := parts[1]

		// Check if this user has any suspicious (non-infra, non-private) IPs.
		hasSuspicious := false
		matches := ipRe.FindAllStringSubmatch(sessionData, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			ip := m[1]
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() {
				continue
			}
			if isInfraIP(ip, infraIPs) {
				continue
			}
			hasSuspicious = true
			break
		}

		if hasSuspicious {
			revokeQuery := fmt.Sprintf(
				"UPDATE %susermeta SET meta_value='' WHERE user_id=%s AND meta_key='session_tokens'",
				prefix, escapeSQLString(userID))
			runMySQLQuery(creds, revokeQuery)
			revoked++
		}
	}

	return revoked
}

// backupAndCleanOption saves the original value to a backup option, then
// removes malicious script injections from the option value.
func backupAndCleanOption(creds wpDBCreds, prefix, optionName, originalValue, maliciousURL string) bool {
	cleaned := removeMaliciousScripts(originalValue)
	if cleaned == originalValue {
		return false
	}

	// Save original value as a backup option (csm_backup_<name>_<timestamp>).
	backupName := fmt.Sprintf("csm_backup_%s_%d", optionName, time.Now().Unix())
	if len(backupName) > 191 {
		backupName = backupName[:191]
	}
	backupQuery := fmt.Sprintf(
		"INSERT INTO %soptions (option_name, option_value, autoload) VALUES ('%s', '%s', 'no')",
		prefix, escapeSQLString(backupName), escapeSQLString(originalValue))
	runMySQLQuery(creds, backupQuery)

	// Write the cleaned value.
	updateQuery := fmt.Sprintf(
		"UPDATE %soptions SET option_value='%s' WHERE option_name='%s'",
		prefix, escapeSQLString(cleaned), escapeSQLString(optionName))
	runMySQLQuery(creds, updateQuery)

	return true
}

// --- Script removal ---

// maliciousScriptRe matches the style-break injection pattern:
// </style><script src=...></script><style>
var maliciousScriptRe = regexp.MustCompile(
	`(?i)</style>\s*<script[^>]*src\s*=\s*[^>]+>\s*</script>\s*<style>`)

// simpleScriptRe matches standalone <script src="..."></script> tags.
var simpleScriptRe = regexp.MustCompile(
	`(?i)<script[^>]*src\s*=\s*["']?https?://[^"'\s>]+["']?[^>]*>\s*</script>`)

// removeMaliciousScripts strips malicious <script> injections from content,
// preserving scripts from known safe domains.
func removeMaliciousScripts(content string) string {
	// First pass: remove style-break pattern (always malicious).
	content = maliciousScriptRe.ReplaceAllString(content, "")

	// Second pass: remove standalone script tags with non-safe domains.
	content = simpleScriptRe.ReplaceAllStringFunc(content, func(match string) string {
		urls := scriptSrcRe.FindStringSubmatch(match)
		if len(urls) >= 2 && !isSafeScriptDomain(urls[1]) {
			return ""
		}
		return match
	})

	return strings.TrimSpace(content)
}

// escapeSQLString escapes special characters for MySQL string interpolation.
func escapeSQLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, "\x00", `\0`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\x1a", `\Z`)
	return s
}
