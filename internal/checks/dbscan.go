package checks

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// Malicious patterns in WordPress database content.
//
// requiresExternalScript: when true, a matching row is only reported if
// its content also contains a <script src=...> pointing at a domain NOT
// on the known-safe list. This filters out the legitimate analytics and
// widget embeds that site owners place in page content (Google Tag
// Manager, Google merchant badge, HubSpot, Mailchimp, etc.) without
// weakening detection of attacker-injected external loaders.
var dbMalwarePatterns = []struct {
	pattern                string
	severity               alert.Severity
	desc                   string
	requiresExternalScript bool
}{
	// The script-tag entry catches BOTH inline <script> blocks and
	// <script src=...> loaders as a fast LIKE pre-filter; the Go post-
	// filter (hasMaliciousExternalScript) verifies the presence of a
	// non-safe-domain external src before raising a finding. Inline
	// obfuscation without an external src is caught by the subsequent
	// code-pattern entries below.
	{"<script", alert.High, "injected <script> tag with non-safe external src", true},
	{"eval(", alert.High, "eval() in database content", false},
	{"base64_decode", alert.High, "base64_decode in database content", false},
	{"document.write(", alert.High, "document.write injection", false},
	{"String.fromCharCode", alert.High, "JavaScript obfuscation (fromCharCode)", false},
	{".workers.dev", alert.Critical, "Cloudflare Workers exfiltration URL", false},
	{"gist.githubusercontent.com", alert.Critical, "GitHub Gist payload URL", false},
	{"pastebin.com/raw", alert.Critical, "Pastebin payload URL", false},
}

// CheckDatabaseContent scans WordPress databases for injected malware,
// spam content, siteurl hijacking, and rogue admin accounts.
func CheckDatabaseContent(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	wpConfigs, _ := osFS.Glob("/home/*/public_html/wp-config.php")
	if len(wpConfigs) == 0 {
		return nil
	}

	for _, wpConfig := range wpConfigs {
		user := extractUser(filepath.Dir(wpConfig))
		creds := parseWPConfig(wpConfig)
		if creds.dbName == "" || creds.dbUser == "" {
			continue
		}

		prefix := creds.tablePrefix
		if prefix == "" {
			prefix = "wp_"
		}

		// 1. Check wp_options for siteurl/home hijacking
		findings = append(findings, checkWPOptions(user, creds, prefix)...)

		// 2. Check wp_posts for injected scripts/malware
		findings = append(findings, checkWPPosts(user, creds, prefix)...)

		// 3. Check wp_users for rogue admin accounts
		findings = append(findings, checkWPUsers(user, creds, prefix)...)
	}

	return findings
}

type wpDBCreds struct {
	dbName      string
	dbUser      string
	dbPass      string
	dbHost      string
	tablePrefix string
}

// parseWPConfig extracts database credentials from wp-config.php.
func parseWPConfig(path string) wpDBCreds {
	f, err := osFS.Open(path)
	if err != nil {
		return wpDBCreds{}
	}
	defer func() { _ = f.Close() }()

	var creds wpDBCreds
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Match: define( 'DB_NAME', 'value' );
		if val := extractDefine(line, "DB_NAME"); val != "" {
			creds.dbName = val
		}
		if val := extractDefine(line, "DB_USER"); val != "" {
			creds.dbUser = val
		}
		if val := extractDefine(line, "DB_PASSWORD"); val != "" {
			creds.dbPass = val
		}
		if val := extractDefine(line, "DB_HOST"); val != "" {
			creds.dbHost = val
		}

		// Match: $table_prefix = 'wp_';
		if strings.Contains(line, "$table_prefix") {
			if val := extractPHPString(line); val != "" {
				creds.tablePrefix = val
			}
		}
	}

	if creds.dbHost == "" {
		creds.dbHost = "localhost"
	}

	return creds
}

// extractDefine extracts the value from: define( 'KEY', 'value' );
func extractDefine(line, key string) string {
	if !strings.Contains(line, key) {
		return ""
	}
	// Skip comments
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") {
		return ""
	}

	// After the literal key, step past the first comma so
	// extractPHPString picks up the VALUE's opening quote rather than
	// the KEY's trailing closing quote. Without this, on input
	//     define( 'DB_NAME', 'wordpress_db' );
	// extractPHPString would see `', 'wordpress_db' );` and return
	// `, ` — the substring between the closing quote of 'DB_NAME' and
	// the opening quote of 'wordpress_db'. Every real WordPress
	// install's wp-config.php triggered this, which silently broke
	// the entire WP database scan check.
	rest := line[strings.Index(line, key)+len(key):]
	if commaIdx := strings.Index(rest, ","); commaIdx >= 0 {
		rest = rest[commaIdx+1:]
	}
	return extractPHPString(rest)
}

// extractPHPString extracts the first quoted string value from a line.
func extractPHPString(s string) string {
	// Find opening quote
	for _, quote := range []byte{'\'', '"'} {
		start := strings.IndexByte(s, quote)
		if start < 0 {
			continue
		}
		rest := s[start+1:]
		end := strings.IndexByte(rest, quote)
		if end < 0 {
			continue
		}
		return rest[:end]
	}
	return ""
}

// runMySQLQuery executes a MySQL query and returns the output lines.
func runMySQLQuery(creds wpDBCreds, query string) []string {
	args := []string{
		"-N", "-B", // no headers, tab-separated
		"-u", creds.dbUser,
		"-h", creds.dbHost,
		creds.dbName,
		"-e", query,
	}

	// Set password via environment to avoid command-line exposure
	out, err := runCmdWithEnv("mysql", args, "MYSQL_PWD="+creds.dbPass)
	if err != nil || out == nil {
		return nil
	}

	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// checkWPOptions checks for siteurl/home hijacking and injected JavaScript.
func checkWPOptions(user string, creds wpDBCreds, prefix string) []alert.Finding {
	var findings []alert.Finding

	// Check siteurl and home for hijacking
	query := fmt.Sprintf(
		"SELECT option_name, option_value FROM %soptions WHERE option_name IN ('siteurl', 'home', 'admin_email') LIMIT 10",
		prefix)
	lines := runMySQLQuery(creds, query)

	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		optName := parts[0]
		optValue := strings.ToLower(parts[1])

		// Check if siteurl/home points to a different domain
		if (optName == "siteurl" || optName == "home") &&
			(strings.Contains(optValue, "eval(") || strings.Contains(optValue, "<script")) {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "db_siteurl_hijack",
				Message:  fmt.Sprintf("WordPress %s contains malicious code (account: %s)", optName, user),
				Details:  fmt.Sprintf("Database: %s\n%s = %s", creds.dbName, optName, truncateDB(parts[1], 200)),
			})
		}
	}

	// Path 1: External script URLs in any option — only flag non-safe domains.
	query = fmt.Sprintf(
		"SELECT option_name, option_value FROM %soptions WHERE option_value LIKE '%%<script%%src=%%' LIMIT 20",
		prefix)
	lines = runMySQLQuery(creds, query)

	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		optName := parts[0]
		optValue := parts[1]

		// Skip CSM backup options — they preserve the original malicious
		// content for recovery and should not be re-detected/re-cleaned.
		if strings.HasPrefix(optName, "csm_backup_") {
			continue
		}

		maliciousURL := extractMaliciousScriptURL(optValue)
		if maliciousURL == "" {
			continue
		}

		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "db_options_injection",
			Message:  fmt.Sprintf("Malicious script injection in wp_options '%s' (account: %s)", optName, user),
			Details:  fmt.Sprintf("Database: %s\nOption: %s\nMalicious URL: %s\nContent preview: %s", creds.dbName, optName, maliciousURL, truncateDB(optValue, 200)),
		})
	}

	// Path 2: Inline script/code injection in core WP options that should
	// NEVER contain JavaScript (siteurl, home, blogname, blogdescription).
	coreOpts := "siteurl', 'home', 'blogname', 'blogdescription', 'admin_email"
	codePatterns := "<script"
	query = fmt.Sprintf(
		"SELECT option_name, LEFT(option_value, 500) FROM %soptions WHERE option_name IN ('%s') AND option_value LIKE '%%%s%%'",
		prefix, coreOpts, codePatterns)
	lines = runMySQLQuery(creds, query)

	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "db_options_injection",
			Message:  fmt.Sprintf("Malicious content in core wp_option '%s' (account: %s)", parts[0], user),
			Details:  fmt.Sprintf("Database: %s\nOption: %s\nContent preview: %s", creds.dbName, parts[0], truncateDB(parts[1], 200)),
		})
	}

	return findings
}

// checkWPPosts checks post content for injected scripts and malware.
//
// Two classes of false positive are suppressed compared to a naive LIKE-
// based scan:
//
//   - post_types used for plugin-managed storage (form submissions,
//     revisions, templates, minified bundles) are excluded via the
//     shared nonScannablePostTypes denylist. See dbscan_filters.go for
//     the rationale and the full list.
//
//   - Patterns that match too broadly at the SQL layer (the bare
//     <script substring, and bare-word spam keywords like "cialis")
//     are post-filtered in Go against word-boundary regexes and the
//     known-safe-domain list. Legitimate analytics embeds and
//     substring coincidences ("specialist" containing "cialis") no
//     longer produce findings.
//
// The denylist is defense-in-depth: custom post_types created by a
// theme or plugin remain in scope, so attackers cannot evade by
// inventing a new post_type value.
func checkWPPosts(user string, creds wpDBCreds, prefix string) []alert.Finding {
	var findings []alert.Finding

	postTypeExcl := nonScannablePostTypesSQLList()

	for _, mp := range dbMalwarePatterns {
		// Select ID and content so we can post-filter in Go for the
		// patterns that require it. ID comes first so that if the
		// MySQL client wraps long content across lines we can still
		// join reliably on the first tab.
		query := fmt.Sprintf(
			"SELECT ID, post_content FROM %sposts WHERE post_status='publish' AND post_type NOT IN (%s) AND (post_content LIKE '%%%s%%' OR post_content_filtered LIKE '%%%s%%') LIMIT 20",
			prefix, postTypeExcl, mp.pattern, mp.pattern)
		lines := runMySQLQuery(creds, query)
		if len(lines) == 0 {
			continue
		}

		var confirmedIDs []string
		for _, line := range lines {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) < 2 {
				continue
			}
			postID := parts[0]
			content := parts[1]

			if mp.requiresExternalScript && !hasMaliciousExternalScript(content) {
				// All scripts in this post are inline, or point at a
				// known-safe widget host. Skip.
				continue
			}
			confirmedIDs = append(confirmedIDs, postID)
			if len(confirmedIDs) >= 5 {
				break
			}
		}

		if len(confirmedIDs) == 0 {
			continue
		}

		findings = append(findings, alert.Finding{
			Severity: mp.severity,
			Check:    "db_post_injection",
			Message:  fmt.Sprintf("WordPress posts contain %s (account: %s, %d posts)", mp.desc, user, len(confirmedIDs)),
			Details: fmt.Sprintf("Database: %s\nAffected post IDs: %s\nPattern: %s",
				creds.dbName, strings.Join(confirmedIDs, ", "), mp.pattern),
		})
	}

	// Spam keyword scan. Three-layer filter:
	//
	//   1. SQL LIKE as a fast server-side pre-filter (reduces rows).
	//   2. Word-boundary regex in countCloakedSpamMatches (rejects
	//      substring false positives like "specialist" / "cialis").
	//   3. SEO-context requirement in contentHasSpamContext: a keyword
	//      hit only counts when accompanied by CSS cloaking, an
	//      injection fingerprint, or an external anchor whose URL
	//      path contains the keyword. Bare prose mentions (industry
	//      verticals, advisor bios, product catalogs listing a
	//      pharmaceutical supply chain) do not fire.
	//
	// The context requirement catches the real attack pattern — hidden
	// off-screen div with external commercial link — while leaving
	// legitimate content silent. See spam_context.go for the full
	// signal catalog.
	for _, sp := range dbSpamPatterns {
		query := fmt.Sprintf(
			"SELECT ID, post_content FROM %sposts WHERE post_status='publish' AND post_type NOT IN (%s) AND post_content LIKE '%s' LIMIT 200",
			prefix, postTypeExcl, sp.likeFragment)
		lines := runMySQLQuery(creds, query)
		if len(lines) == 0 {
			continue
		}
		contents := make([]string, 0, len(lines))
		for _, line := range lines {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) < 2 {
				continue
			}
			contents = append(contents, parts[1])
		}
		n := countCloakedSpamMatches(sp, contents)
		if n == 0 {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "db_spam_injection",
			Message:  fmt.Sprintf("WordPress posts contain cloaked spam keyword '%s' (%d posts, account: %s)", sp.keyword, n, user),
			Details:  fmt.Sprintf("Database: %s", creds.dbName),
		})
	}

	return findings
}

// checkWPUsers checks for rogue admin accounts created recently.
func checkWPUsers(user string, creds wpDBCreds, prefix string) []alert.Finding {
	var findings []alert.Finding

	// Find admin users created in the last 7 days
	query := fmt.Sprintf(
		"SELECT u.ID, u.user_login, u.user_email, u.user_registered FROM %susers u "+
			"INNER JOIN %susermeta m ON u.ID = m.user_id "+
			"WHERE m.meta_key = '%scapabilities' AND m.meta_value LIKE '%%administrator%%' "+
			"AND u.user_registered >= DATE_SUB(NOW(), INTERVAL 7 DAY) "+
			"LIMIT 10",
		prefix, prefix, prefix)
	lines := runMySQLQuery(creds, query)

	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) < 3 {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "db_rogue_admin",
			Message:  fmt.Sprintf("New WordPress admin account created in last 7 days: %s (account: %s)", parts[1], user),
			Details: fmt.Sprintf("Database: %s\nUser ID: %s\nLogin: %s\nEmail: %s\nRegistered: %s",
				creds.dbName, parts[0], parts[1], parts[2], safeGet(parts, 3)),
		})
	}

	// Check for admin users with suspicious email patterns
	query = fmt.Sprintf(
		"SELECT u.user_login, u.user_email FROM %susers u "+
			"INNER JOIN %susermeta m ON u.ID = m.user_id "+
			"WHERE m.meta_key = '%scapabilities' AND m.meta_value LIKE '%%administrator%%' "+
			"LIMIT 50",
		prefix, prefix, prefix)
	lines = runMySQLQuery(creds, query)

	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		email := strings.ToLower(parts[1])
		// Flag suspicious admin emails (disposable/temporary email domains)
		suspiciousDomains := []string{
			"tempmail", "guerrillamail", "mailinator", "throwaway",
			"yopmail", "sharklasers", "trashmail", "maildrop",
		}
		for _, sd := range suspiciousDomains {
			if strings.Contains(email, sd) {
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "db_suspicious_admin_email",
					Message:  fmt.Sprintf("WordPress admin '%s' has disposable email (account: %s)", parts[0], user),
					Details:  fmt.Sprintf("Database: %s\nEmail: %s", creds.dbName, email),
				})
				break
			}
		}
	}

	return findings
}

func safeGet(parts []string, idx int) string {
	if idx < len(parts) {
		return parts[idx]
	}
	return ""
}

func truncateDB(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// CleanDatabaseSpam removes known spam/malware patterns from WordPress database content.
// Targets wp_posts and wp_options tables. Returns findings for each cleaned row.
func CleanDatabaseSpam(account string) []alert.Finding {
	var findings []alert.Finding

	wpConfigs, _ := osFS.Glob(filepath.Join("/home", account, "*/wp-config.php"))
	wpConfigs2, _ := osFS.Glob(filepath.Join("/home", account, "public_html/wp-config.php"))
	wpConfigs = append(wpConfigs, wpConfigs2...)

	for _, wpConfig := range wpConfigs {
		creds := parseWPConfig(wpConfig)
		if creds.dbName == "" {
			continue
		}
		prefix := creds.tablePrefix
		if prefix == "" {
			prefix = "wp_"
		}

		// Clean spam from wp_posts
		spamPatterns := []struct {
			pattern string
			desc    string
		}{
			{"<script>", "injected script tag"},
			{"eval(", "eval() in post content"},
			{"base64_decode(", "base64_decode in post content"},
			{"document.write(", "document.write injection"},
		}

		for _, sp := range spamPatterns {
			// Count affected rows first
			countQuery := fmt.Sprintf(
				"SELECT COUNT(*) FROM %sposts WHERE post_content LIKE '%%%s%%'",
				prefix, sp.pattern)
			countLines := runMySQLQuery(creds, countQuery)
			if len(countLines) == 0 || countLines[0] == "0" {
				continue
			}

			// Clean: remove the malicious pattern from post_content
			cleanQuery := fmt.Sprintf(
				"UPDATE %sposts SET post_content = REPLACE(post_content, '%s', '') WHERE post_content LIKE '%%%s%%'",
				prefix, sp.pattern, sp.pattern)
			runMySQLQuery(creds, cleanQuery)

			findings = append(findings, alert.Finding{
				Severity:  alert.High,
				Check:     "db_spam_cleaned",
				Message:   fmt.Sprintf("Cleaned %s from %s posts in %s (account: %s)", sp.desc, countLines[0], creds.dbName, account),
				Timestamp: time.Now(),
			})
		}

		// Scan for spam keywords in wp_posts. Uses the same word-boundary
		// regex + post_type denylist + SEO-context requirement as
		// checkWPPosts so an operator-initiated cleanup surfaces the
		// same set of findings the periodic scan does.
		postTypeExcl := nonScannablePostTypesSQLList()
		for _, sp := range dbSpamPatterns {
			query := fmt.Sprintf(
				"SELECT ID, post_content FROM %sposts WHERE post_status='publish' AND post_type NOT IN (%s) AND post_content LIKE '%s' LIMIT 200",
				prefix, postTypeExcl, sp.likeFragment)
			lines := runMySQLQuery(creds, query)
			if len(lines) == 0 {
				continue
			}
			contents := make([]string, 0, len(lines))
			for _, line := range lines {
				parts := strings.SplitN(line, "\t", 2)
				if len(parts) < 2 {
					continue
				}
				contents = append(contents, parts[1])
			}
			n := countCloakedSpamMatches(sp, contents)
			if n == 0 {
				continue
			}

			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "db_spam_found",
				Message:  fmt.Sprintf("Found spam keyword '%s' in %d published posts in %s (account: %s) - manual review recommended", sp.keyword, n, creds.dbName, account),
			})
		}
	}

	return findings
}
