package checks

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

// AutoRespondDBMalware processes database injection findings and takes
// automated action: blocks attacker IPs extracted from WordPress session
// tokens, revokes compromised user sessions, and cleans confirmed
// malicious content from wp_options or stored database objects.
//
// Only acts on high-confidence findings:
//   - db_options_injection with confirmed malicious external script URLs
//   - db_siteurl_hijack (siteurl/home pointing to malicious content)
//   - db_malicious_trigger/event/procedure/function with structured metadata
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
		case "db_malicious_trigger", "db_malicious_event",
			"db_malicious_procedure", "db_malicious_function":
			acts := handleMaliciousDBObject(f)
			actions = append(actions, acts...)
		}
	}

	return actions
}

// dbDropObjectFn is the seam through which handleMaliciousDBObject performs
// the backup-then-DROP. Overridden in tests so the routing and action
// emission can be exercised without a live MySQL server.
var dbDropObjectFn = DBDropObject

// handleMaliciousDBObject auto-cleans a confirmed malicious stored database
// object (trigger/event/procedure/function). Detection always fires; the
// DROP only runs when the operator has enabled auto_response.clean_database
// (checked by the caller). The object kind comes from the check name
// (db_malicious_<kind>); account/schema/name come from the finding details.
// DBDropObject records a SHOW CREATE backup in bbolt before dropping, so the
// action is reversible.
func handleMaliciousDBObject(f alert.Finding) []alert.Finding {
	kind := maliciousDBObjectKind(f.Check)
	if kind == "" {
		return nil
	}
	account, schema, detailKind, name := parseDBObjectFindingDetails(f.Details)
	if account == "" || schema == "" || detailKind == "" || name == "" {
		return nil
	}
	if detailKind != kind {
		return nil
	}

	res := dbDropObjectFn(account, schema, kind, name, false)
	if !res.Success {
		return []alert.Finding{{
			Severity:  alert.Warning,
			Check:     "auto_response",
			Message:   fmt.Sprintf("AUTO-DB-CLEAN failed to drop %s %s.%s: %s", kind, schema, name, res.Message),
			Timestamp: time.Now(),
		}}
	}
	return []alert.Finding{{
		Severity:  alert.Warning,
		Check:     "auto_response",
		Message:   fmt.Sprintf("AUTO-DB-CLEAN: Dropped malicious %s %s.%s (backup retained for restore)", kind, schema, name),
		Timestamp: time.Now(),
	}}
}

func maliciousDBObjectKind(check string) string {
	const prefix = "db_malicious_"
	if !strings.HasPrefix(check, prefix) {
		return ""
	}
	kind := strings.TrimPrefix(check, prefix)
	if !IsDBObjectKind(kind) {
		return ""
	}
	return kind
}

// parseDBObjectFindingDetails extracts the structured header fields a
// db_malicious_<kind> finding carries in its Details block. The SQL body is
// attacker-controlled and may contain lines that look like metadata, so parsing
// stops at Body and keeps the first value for each header key.
func parseDBObjectFindingDetails(details string) (account, schema, kind, name string) {
	for _, line := range strings.Split(details, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Body:") {
			break
		}
		switch {
		case strings.HasPrefix(line, "Account: "):
			if account == "" {
				account = strings.TrimSpace(strings.TrimPrefix(line, "Account: "))
			}
		case strings.HasPrefix(line, "Schema: "):
			if schema == "" {
				schema = strings.TrimSpace(strings.TrimPrefix(line, "Schema: "))
			}
		case strings.HasPrefix(line, "Kind: "):
			if kind == "" {
				kind = strings.TrimSpace(strings.TrimPrefix(line, "Kind: "))
			}
		case strings.HasPrefix(line, "Name: "):
			if name == "" {
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name: "))
			}
		}
	}
	return
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

	// 1. Extract and block attacker IPs from active WP sessions through the
	// real auto-block path (dry-run, rate limits, and allowlists all apply).
	suspiciousIPs := extractSuspiciousSessionIPs(creds, prefix, cfg.InfraIPs)
	actions = append(actions, blockSessionAttackerIPs(cfg, suspiciousIPs,
		fmt.Sprintf("active WP session on compromised site, DB: %s", dbName))...)

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
	actions = append(actions, blockSessionAttackerIPs(cfg, suspiciousIPs,
		fmt.Sprintf("active session on hijacked site, DB: %s", dbName))...)

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

// blockSessionAttackerIPs routes attacker IPs recovered from active WordPress
// sessions through the standard auto-block path so each one lands as a real
// firewall block subject to dry-run, rate limiting, allowlists, and the
// expiring threat record. It returns the genuine AUTO-BLOCK / dry-run findings
// AutoBlockIPs emits.
//
// The synthetic findings carry the local_threat_score check -- an existing
// always-block signal meaning "this IP is a confirmed local threat" -- plus a
// structured SourceIP, so AutoBlockIPs blocks exactly that address. Emitting a
// fabricated "auto_block: AUTO-BLOCK <ip>" finding here instead -- as the code
// once did -- never blocked anything, yet alert.FilterBlockedAlerts trusted it
// as proof-of-block and suppressed the IP's reputation alert, so the address was
// neither blocked nor surfaced.
func blockSessionAttackerIPs(cfg *config.Config, ips []string, siteContext string) []alert.Finding {
	if len(ips) == 0 {
		return nil
	}
	findings := make([]alert.Finding, 0, len(ips))
	for _, ip := range ips {
		findings = append(findings, alert.Finding{
			Severity:  alert.Critical,
			Check:     "local_threat_score",
			Message:   fmt.Sprintf("attacker session IP %s (%s)", ip, siteContext),
			SourceIP:  ip,
			Timestamp: time.Now(),
		})
	}
	return AutoBlockIPs(cfg, findings)
}

// --- URL analysis ---

// scriptSrcRe matches <script src="..."> or <script src=...> patterns.
// Accepts https://, http://, and protocol-relative // URLs, since real
// attackers use all three forms to load external payloads.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']?((?:https?:)?//[^"'\s>]+)`)

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
// that is classified as an attacker script by isAttackerScriptURL.
//
// The classification uses an attack-indicator model (see url_reputation.go):
// a URL flags only when it shows attacker-characteristic markers (raw IP
// host, abused TLD, plaintext HTTP, known-bad exfil host, or no valid
// TLD). The previous allowlist-only model produced HIGH-severity findings
// for legitimate third-party widgets (OneTrust, Issuu, regional video
// embeds, regional tax-form widgets) whose domains were not on the
// allowlist; the attack-indicator model eliminates those false positives
// while still catching the injection patterns attackers actually use.
//
// knownSafeDomains is retained as a fast-path optimisation and operator-
// pre-approved list — see isAttackerScriptURL for the composition order.
func extractMaliciousScriptURL(content string) string {
	matches := scriptSrcRe.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		url := match[1]
		if isAttackerScriptURL(url) {
			return url
		}
	}
	return ""
}

// isSafeScriptDomain checks if a script URL is from a known safe domain.
// Handles https://host, http://host, //host (protocol-relative), and
// host-with-port forms.
func isSafeScriptDomain(url string) bool {
	urlLower := strings.ToLower(url)
	urlLower = strings.TrimPrefix(urlLower, "https://")
	urlLower = strings.TrimPrefix(urlLower, "http://")
	urlLower = strings.TrimPrefix(urlLower, "//")
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
// Skips wp-configs whose $table_prefix fails the safety check -- those
// values come straight from a cPanel-user-writable file and end up in
// root-credentialled SQL via handleMaliciousOption / handleSiteurlHijack.
func findCredsForDB(dbName string) wpDBCreds {
	wpConfigs, _ := osFS.Glob("/home/*/public_html/wp-config.php")
	addonConfigs, _ := osFS.Glob("/home/*/*/wp-config.php")
	wpConfigs = append(wpConfigs, addonConfigs...)

	for _, path := range wpConfigs {
		creds := parseWPConfig(path)
		if creds.dbName != dbName {
			continue
		}
		prefix, ok := resolveTablePrefix(creds)
		if !ok {
			continue
		}
		creds.tablePrefix = prefix
		return creds
	}
	return wpDBCreds{}
}

// readOptionValue reads the full value of a wp_option from the database.
//
// mysqlclient returns mysql batch-mode output, where control bytes are rendered
// as escape sequences (a real newline becomes the two bytes "\n"). The value is
// unescaped back to its true bytes before returning so callers that write it
// back (the backup copy and the cleaned value) persist the original content
// rather than the escaped text, keeping PHP-serialized length prefixes valid.
//
// This path intentionally bypasses runMySQLQuery: that legacy scan helper trims
// each returned row before handing it to callers, but wp_options values may
// contain significant leading/trailing whitespace that must survive byte-for-
// byte when CSM writes the backup and cleaned option value.
func readOptionValue(creds wpDBCreds, prefix, optionName string) string {
	if !isValidOptionName(optionName) {
		return ""
	}
	query := fmt.Sprintf(
		"SELECT option_value FROM %soptions WHERE option_name='%s' LIMIT 1",
		prefix, escapeSQLString(optionName))
	lines, err := mysqlclient.PerAccountQuery(context.Background(), mysqlclient.Creds{
		User:     creds.dbUser,
		Password: creds.dbPass,
		Host:     creds.dbHost,
		DBName:   creds.dbName,
	}, query)
	if err != nil {
		return ""
	}
	if len(lines) == 0 {
		return ""
	}
	return mysqlclient.BatchUnescape(lines[0])
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
	if maliciousURL == "" {
		return false
	}

	cleaned := removeMaliciousScripts(originalValue)
	// Never claim a clean (nor write back) unless the confirmed attacker
	// script is actually gone. This keeps removal locked to detection: if
	// a script form is flagged but the remover cannot strip it, report the
	// finding but never persist a value that still carries a live payload.
	// Plain text references to the same URL are inert option data and must
	// not block a valid script cleanup.
	if extractMaliciousScriptURL(cleaned) != "" {
		return false
	}
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
// The src grammar mirrors scriptSrcRe (https://, http://, and
// protocol-relative //) so removal stays paired with detection: a URL
// form the detector flags must be one the remover can strip.
var simpleScriptRe = regexp.MustCompile(
	`(?i)<script[^>]*src\s*=\s*["']?(?:https?:)?//[^"'\s>]+["']?[^>]*>\s*</script>`)

// removeMaliciousScripts strips malicious <script> injections from content,
// preserving scripts that are not classified as attacker scripts.
//
// Uses the same isAttackerScriptURL predicate as extractMaliciousScriptURL
// so detection and removal stay semantically paired. If the detector
// would not flag a given URL as malicious, the remover must not strip
// it — otherwise an operator running DBCleanOption on an option that
// contains a real injection alongside a legitimate third-party embed
// (OneTrust, Issuu, regional widget) would silently lose the legitimate
// embed along with the attacker's script.
func removeMaliciousScripts(content string) string {
	// First pass: remove style-break patterns only when the embedded URL has
	// attacker indicators. The wrapper is suspicious, but the cleaner must
	// not remove a legitimate embed just because it appears next to a real
	// attacker script in the same option.
	content = maliciousScriptRe.ReplaceAllStringFunc(content, func(match string) string {
		urls := scriptSrcRe.FindStringSubmatch(match)
		if len(urls) >= 2 && isAttackerScriptURL(urls[1]) {
			return ""
		}
		return match
	})

	// Second pass: remove standalone script tags only when the URL
	// shows attacker indicators.
	content = simpleScriptRe.ReplaceAllStringFunc(content, func(match string) string {
		urls := scriptSrcRe.FindStringSubmatch(match)
		if len(urls) >= 2 && isAttackerScriptURL(urls[1]) {
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
