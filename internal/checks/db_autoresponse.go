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
			acts := handleMaliciousOption(f)
			actions = append(actions, acts...)
		case "db_siteurl_hijack":
			acts := handleSiteurlHijack(f)
			actions = append(actions, acts...)
		}
	}

	return actions
}

// handleMaliciousOption checks if a db_options_injection finding contains
// a confirmed malicious external script URL, and if so:
// 1. Extracts the malicious URL
// 2. Finds active WP user sessions and blocks their IPs
// 3. Cleans the malicious content from the option
func handleMaliciousOption(f alert.Finding) []alert.Finding {
	var actions []alert.Finding

	// Extract database name and option name from the finding details.
	dbName, optionName := parseDBFindingDetails(f.Details)
	if dbName == "" || optionName == "" {
		return nil
	}

	// Only act on options with confirmed malicious external script URLs.
	// This extracts <script src="..."> URLs and checks them against known
	// malicious patterns. Legitimate services (GTM, Analytics, Mailchimp)
	// are explicitly excluded.
	maliciousURL := extractMaliciousScriptURL(f.Details)
	if maliciousURL == "" {
		return nil
	}

	// Resolve credentials for this database.
	creds := findCredsForDB(dbName)
	if creds.dbName == "" {
		return nil
	}

	prefix := creds.tablePrefix
	if prefix == "" {
		prefix = "wp_"
	}

	// 1. Block attacker IPs from active WP sessions.
	sessionIPs := extractWPSessionIPs(creds, prefix)
	for _, ip := range sessionIPs {
		actions = append(actions, alert.Finding{
			Severity:  alert.Critical,
			Check:     "auto_response",
			Message:   fmt.Sprintf("AUTO-BLOCK: %s (active WP session on compromised site, DB: %s)", ip, dbName),
			Timestamp: time.Now(),
		})
	}

	// 2. Revoke all WP user sessions.
	revokeAllWPSessions(creds, prefix)
	actions = append(actions, alert.Finding{
		Severity:  alert.Warning,
		Check:     "auto_response",
		Message:   fmt.Sprintf("AUTO-DB-CLEAN: Revoked all WordPress sessions (DB: %s, malicious URL: %s)", dbName, maliciousURL),
		Timestamp: time.Now(),
	})

	// 3. Clean the malicious option content.
	cleaned := cleanMaliciousOption(creds, prefix, optionName)
	if cleaned {
		actions = append(actions, alert.Finding{
			Severity:  alert.Warning,
			Check:     "auto_response",
			Message:   fmt.Sprintf("AUTO-DB-CLEAN: Removed malicious script from wp_options '%s' (DB: %s)", optionName, dbName),
			Timestamp: time.Now(),
		})
	}

	return actions
}

// handleSiteurlHijack handles siteurl/home hijacking by revoking sessions.
// Does NOT modify siteurl/home values — that requires manual intervention
// because an incorrect fix would break the site entirely.
func handleSiteurlHijack(f alert.Finding) []alert.Finding {
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

	// Block session IPs and revoke sessions.
	sessionIPs := extractWPSessionIPs(creds, prefix)
	for _, ip := range sessionIPs {
		actions = append(actions, alert.Finding{
			Severity:  alert.Critical,
			Check:     "auto_response",
			Message:   fmt.Sprintf("AUTO-BLOCK: %s (active session on hijacked site, DB: %s)", ip, dbName),
			Timestamp: time.Now(),
		})
	}

	revokeAllWPSessions(creds, prefix)
	actions = append(actions, alert.Finding{
		Severity:  alert.Warning,
		Check:     "auto_response",
		Message:   fmt.Sprintf("AUTO-DB-CLEAN: Revoked all WordPress sessions on hijacked site (DB: %s)", dbName),
		Timestamp: time.Now(),
	})

	return actions
}

// --- URL analysis ---

// scriptSrcRe matches <script src="..."> or <script src=...> patterns.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']?(https?://[^"'\s>]+)`)

// knownSafeDomains are legitimate services that embed scripts in wp_options.
// These are checked as suffixes to handle subdomains (e.g., chimpstatic.com).
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
	"mautic.net",
	"pinterest.com",
	"twitter.com",
	"linkedin.com",
	"addthis.com",
	"sharethis.com",
	"recaptcha.net",
}

// extractMaliciousScriptURL finds a <script src="..."> URL in the content
// that is NOT from a known safe domain. Returns the URL if found, empty if
// all scripts are from safe domains or no scripts found.
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
	// Extract hostname from URL.
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

// --- DB helpers ---

// parseDBFindingDetails extracts the database name and option name from
// a finding's Details field (format: "Database: X\nOption: Y\n...").
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

// findCredsForDB finds wp-config.php credentials that match a given database name.
func findCredsForDB(dbName string) wpDBCreds {
	wpConfigs, _ := osFS.Glob("/home/*/public_html/wp-config.php")
	// Also check addon domains.
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

// extractWPSessionIPs reads all active WordPress user session tokens
// and extracts the IP addresses. Returns deduplicated IPs.
func extractWPSessionIPs(creds wpDBCreds, prefix string) []string {
	query := fmt.Sprintf(
		"SELECT meta_value FROM %susermeta WHERE meta_key='session_tokens' AND meta_value != ''",
		prefix)
	lines := runMySQLQuery(creds, query)

	seen := make(map[string]bool)
	var ips []string

	// WordPress stores sessions as serialized PHP arrays containing IP addresses.
	// Extract IPs with a simple regex rather than parsing PHP serialization.
	ipRe := regexp.MustCompile(`"ip";s:\d+:"([^"]+)"`)

	for _, line := range lines {
		matches := ipRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			ip := m[1]
			// Validate it's a real IP and not loopback/private.
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() {
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

// revokeAllWPSessions clears all session_tokens in wp_usermeta,
// effectively logging out all WordPress users.
func revokeAllWPSessions(creds wpDBCreds, prefix string) {
	query := fmt.Sprintf(
		"UPDATE %susermeta SET meta_value='' WHERE meta_key='session_tokens'",
		prefix)
	runMySQLQuery(creds, query)
}

// cleanMaliciousOption removes malicious <script> injections from a
// wp_options value. Preserves any legitimate content around the injection.
// Returns true if the option was successfully cleaned.
func cleanMaliciousOption(creds wpDBCreds, prefix, optionName string) bool {
	// Read current value.
	query := fmt.Sprintf(
		"SELECT option_value FROM %soptions WHERE option_name='%s' LIMIT 1",
		prefix, escapeSQLString(optionName))
	lines := runMySQLQuery(creds, query)
	if len(lines) == 0 {
		return false
	}

	original := lines[0]

	// Remove malicious script tags (including the style-break pattern).
	// Pattern: </style><script src=...></script><style>
	cleaned := removeMaliciousScripts(original)
	if cleaned == original {
		return false // nothing to clean
	}

	// Write back the cleaned value.
	updateQuery := fmt.Sprintf(
		"UPDATE %soptions SET option_value='%s' WHERE option_name='%s'",
		prefix, escapeSQLString(cleaned), escapeSQLString(optionName))
	runMySQLQuery(creds, updateQuery)

	return true
}

// maliciousScriptRe matches injected script tags, including the common
// style-break pattern: </style><script src=...></script><style>
var maliciousScriptRe = regexp.MustCompile(
	`(?i)</style>\s*<script[^>]*src\s*=\s*[^>]+>\s*</script>\s*<style>`)

// simpleScriptRe matches standalone <script src="malicious.example.com">
var simpleScriptRe = regexp.MustCompile(
	`(?i)<script[^>]*src\s*=\s*["']?https?://[^"'\s>]+["']?[^>]*>\s*</script>`)

// removeMaliciousScripts strips malicious <script> injections from content,
// preserving legitimate scripts from known safe domains.
func removeMaliciousScripts(content string) string {
	// First pass: remove style-break pattern (always malicious).
	content = maliciousScriptRe.ReplaceAllString(content, "")

	// Second pass: remove standalone script tags with non-safe domains.
	content = simpleScriptRe.ReplaceAllStringFunc(content, func(match string) string {
		urls := scriptSrcRe.FindStringSubmatch(match)
		if len(urls) >= 2 && !isSafeScriptDomain(urls[1]) {
			return ""
		}
		return match // keep safe scripts
	})

	return strings.TrimSpace(content)
}

// escapeSQLString escapes single quotes for safe SQL string interpolation.
// This is used for UPDATE queries where parameterized queries aren't
// available through the mysql CLI.
func escapeSQLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s
}
