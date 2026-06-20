package checks

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// Per-finding Re-check for the database-content family.
//
// These verifiers re-evaluate a single database finding against the live
// database and clear it only on confirmed evidence -- the row is gone, or its
// current value no longer matches the detector that raised it. The cardinal
// rule is the same as the filesystem re-checks: NEVER false-resolve. Clearing a
// db_* finding auto-dismisses a live database compromise, so any ambiguity
// (connection failure, query error, a site we can no longer locate, an
// unparseable finding) returns Checked:false and leaves the finding in place
// for a full account scan.
//
// Reliability over the wp-config password: re-checks query as root against the
// finding's schema (mysqlclient.RootQuerySchema) rather than the per-account
// credentials in the CMS config file, which drift on cPanel password rotations.
// The config file is read only to re-discover the schema name and table prefix.

// dbVerifyTimeout bounds a single synchronous database re-check.
var dbVerifyTimeout = 30 * time.Second

// validAccountName guards an account name parsed out of finding text before it
// is interpolated into a /home/<account>/... glob.
var validAccountName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)

// messageAccountRe pulls account tokens out of WordPress finding messages.
var messageAccountRe = regexp.MustCompile(`(^|[,(])\s*account:\s*([A-Za-z][A-Za-z0-9_-]{0,31})([,)]|$)`)

// detailField returns the value of a "Key: value" line in a finding's Details
// block, or "" when the key is absent. The key match is case-sensitive and the
// value is whitespace-trimmed.
func detailField(details, key string) string {
	value, ok := detailFieldPresent(details, key)
	if !ok {
		return ""
	}
	return value
}

func detailFieldPresent(details, key string) (string, bool) {
	want := key + ":"
	for _, line := range strings.Split(details, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, want) {
			return strings.TrimSpace(line[len(want):]), true
		}
	}
	return "", false
}

// dbFindingAccount resolves the cPanel account a database finding belongs to.
// CMS, DB-object, and admin findings carry it as an "Account:" detail line; the
// WordPress content findings carry it only in the message "(account: <user>)".
func dbFindingAccount(message, details string) string {
	if a, ok := detailFieldPresent(details, "Account"); ok {
		return validFindingAccount(a)
	}
	matches := messageAccountRe.FindAllStringSubmatch(message, -1)
	if len(matches) > 0 {
		return matches[len(matches)-1][2]
	}
	return ""
}

func validFindingAccount(account string) string {
	account = strings.TrimSpace(account)
	if !validAccountName.MatchString(account) {
		return ""
	}
	return account
}

// runDBVerifyQueryRoot runs a root-credential query against an explicit schema
// and returns the rows plus the error. Unlike runMySQLQueryRoot (which collapses
// any error into a nil slice), this preserves the error so a re-check can tell
// "query ran, zero rows" (the row is gone/clean -> safe to resolve) apart from
// "query failed" (DB down, connection refused -> must NOT resolve).
func runDBVerifyQueryRoot(schema, query string, args ...any) ([]string, error) {
	if strings.TrimSpace(schema) == "" {
		return nil, fmt.Errorf("empty schema")
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbVerifyTimeout)
	defer cancel()
	return mysqlclient.RootQuerySchema(ctx, schema, query, args...)
}

// dbVerifyQueryError is the standard Checked:false result for a failed re-check
// query. The raw error is intentionally not surfaced to the operator (it can
// carry DSN/host internals); the generic guidance is enough to act on.
func dbVerifyQueryError() VerifyResult {
	return VerifyResult{Checked: false, Detail: "could not query the database (try again, or run an account scan)"}
}

// dbVerifyNotLocatable is the standard Checked:false result when the re-check
// cannot re-discover the install (site removed, DB renamed, config unreadable).
func dbVerifyNotLocatable(kind string) VerifyResult {
	return VerifyResult{Checked: false, Detail: fmt.Sprintf("could not locate the %s to re-check (run an account scan)", kind)}
}

// findWPVerifyPrefixes re-discovers the WordPress install for account whose
// database matches dbName, returning the table prefixes a verifier should query.
// New findings carry an exact Table prefix detail. Older findings do not, so the
// fallback enumerates every prefix in that WordPress install, including active
// multisite secondary blogs. ok=false means the caller refuses to guess.
func findWPVerifyPrefixes(account, dbName, details string) (prefixes []string, ok bool) {
	if !validAccountName.MatchString(account) || dbName == "" {
		return nil, false
	}
	patterns := []string{fmt.Sprintf("/home/%s/public_html/wp-config.php", account)}
	addon, _ := osFS.Glob(fmt.Sprintf("/home/%s/*/wp-config.php", account))
	patterns = append(patterns, addon...)

	targetPrefix := detailField(details, "Table prefix")
	if targetPrefix != "" && !validTablePrefix.MatchString(targetPrefix) {
		return nil, false
	}

	seen := map[string]bool{}
	for _, path := range patterns {
		creds := parseWPConfig(path)
		if creds.dbName != dbName {
			continue
		}
		p, ok := resolveTablePrefix(creds)
		if !ok {
			return nil, false
		}
		if targetPrefix != "" {
			if wpVerifyPrefixMatchesBase(targetPrefix, p) {
				return []string{targetPrefix}, true
			}
			continue
		}
		addPrefix(&prefixes, seen, p)
		if creds.multisite {
			multisitePrefixes, err := wpVerifyMultisitePrefixes(dbName, p)
			if err != nil {
				return nil, false
			}
			for _, prefix := range multisitePrefixes {
				addPrefix(&prefixes, seen, prefix)
			}
		}
	}
	if len(prefixes) == 0 {
		return nil, false
	}
	return prefixes, true
}

func addPrefix(prefixes *[]string, seen map[string]bool, prefix string) {
	if seen[prefix] {
		return
	}
	seen[prefix] = true
	*prefixes = append(*prefixes, prefix)
}

func wpVerifyPrefixMatchesBase(prefix, base string) bool {
	if prefix == base {
		return true
	}
	if !strings.HasPrefix(prefix, base) || !strings.HasSuffix(prefix, "_") {
		return false
	}
	blogID := strings.TrimSuffix(strings.TrimPrefix(prefix, base), "_")
	return isAllDigits(blogID)
}

func wpVerifyMultisitePrefixes(dbName, basePrefix string) ([]string, error) {
	rows, err := runDBVerifyQueryRoot(dbName, fmt.Sprintf(
		"SELECT blog_id FROM `%sblogs` WHERE archived = 0 AND deleted = 0 AND spam = 0 AND blog_id != 1",
		basePrefix,
	))
	if err != nil {
		return nil, err
	}
	var prefixes []string
	for _, row := range rows {
		blogID := strings.TrimSpace(row)
		if blogID == "" || blogID == "1" || !isAllDigits(blogID) {
			continue
		}
		prefixes = append(prefixes, fmt.Sprintf("%s%s_", basePrefix, blogID))
	}
	return prefixes, nil
}

// dbInjectionCoreOptions are the wp_options names that must never carry a
// <script> tag (mirrors the Path-2 core-option check in checkWPOptions).
var dbInjectionCoreOptions = map[string]bool{
	"siteurl": true, "home": true, "blogname": true,
	"blogdescription": true, "admin_email": true,
}

// verifyDBOptionsInjection re-reads the flagged wp_options row and resolves the
// finding when the option is gone or no longer carries an injected external
// script (mirrors checkWPOptions' two detection paths).
func verifyDBOptionsInjection(message, details string) VerifyResult {
	dbName := detailField(details, "Database")
	optName := detailField(details, "Option")
	if optName == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the option name from the finding"}
	}
	prefixes, ok := findWPVerifyPrefixes(dbFindingAccount(message, details), dbName, details)
	if !ok {
		return dbVerifyNotLocatable("WordPress site")
	}
	present := false
	for _, prefix := range prefixes {
		rows, err := runDBVerifyQueryRoot(dbName,
			fmt.Sprintf("SELECT option_value FROM `%soptions` WHERE option_name = ?", prefix), optName)
		if err != nil {
			return dbVerifyQueryError()
		}
		for _, row := range rows {
			present = true
			if optionValueStillMalicious(optName, row) {
				return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("option %q still contains injected content", optName)}
			}
		}
	}
	if !present {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("option %q is no longer present", optName)}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("option %q no longer contains injected content", optName)}
}

func optionValueStillMalicious(optName, value string) bool {
	if extractMaliciousScriptURL(value) != "" {
		return true
	}
	if dbInjectionCoreOptions[optName] && strings.Contains(strings.ToLower(value), "<script") {
		return true
	}
	return false
}

// verifyDBSiteurlHijack re-reads the flagged siteurl/home option and resolves
// when the option is gone or no longer carries eval()/<script> (mirrors the
// siteurl-hijack branch of checkWPOptions).
func verifyDBSiteurlHijack(message, details string) VerifyResult {
	dbName := detailField(details, "Database")
	optName := siteurlOptionFromDetails(details)
	if optName == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the option name from the finding"}
	}
	prefixes, ok := findWPVerifyPrefixes(dbFindingAccount(message, details), dbName, details)
	if !ok {
		return dbVerifyNotLocatable("WordPress site")
	}
	present := false
	for _, prefix := range prefixes {
		rows, err := runDBVerifyQueryRoot(dbName,
			fmt.Sprintf("SELECT option_value FROM `%soptions` WHERE option_name = ?", prefix), optName)
		if err != nil {
			return dbVerifyQueryError()
		}
		for _, row := range rows {
			present = true
			if siteurlValueStillMalicious(row) {
				return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("option %q still contains malicious code", optName)}
			}
		}
	}
	if !present {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("option %q is no longer present", optName)}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("option %q no longer contains malicious code", optName)}
}

func siteurlValueStillMalicious(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "eval(") || strings.Contains(lower, "<script")
}

// siteurlOptionFromDetails extracts the option name from a db_siteurl_hijack
// detail block whose body line is "<optName> = <value>". The detector only ever
// emits siteurl or home; any other shape returns "".
func siteurlOptionFromDetails(details string) string {
	for _, line := range strings.Split(details, "\n") {
		line = strings.TrimSpace(line)
		for _, opt := range []string{"siteurl", "home"} {
			if strings.HasPrefix(line, opt+" =") {
				return opt
			}
		}
	}
	return ""
}

// verifyDBPostInjection re-reads the affected published posts and resolves the
// finding when none of them still match the injected pattern (mirrors
// checkWPPosts' post-status, post-type, and external-script filters).
func verifyDBPostInjection(message, details string) VerifyResult {
	dbName := detailField(details, "Database")
	ids := parsePostIDList(detailField(details, "Affected post IDs"))
	pattern := detailField(details, "Pattern")
	if len(ids) == 0 || pattern == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the affected posts from the finding"}
	}
	requiresExternalScript, ok := lookupMalwarePattern(pattern)
	if !ok {
		return VerifyResult{Checked: false, Detail: "finding pattern is not auto-verifiable"}
	}
	prefixes, ok := findWPVerifyPrefixes(dbFindingAccount(message, details), dbName, details)
	if !ok {
		return dbVerifyNotLocatable("WordPress site")
	}
	placeholders, args := inClausePlaceholders(ids)
	stillInjected := 0
	for _, prefix := range prefixes {
		rows, err := runDBVerifyQueryRoot(dbName,
			fmt.Sprintf("SELECT ID, post_content, post_content_filtered FROM `%sposts` WHERE ID IN (%s) AND post_status='publish' AND post_type NOT IN (%s)",
				prefix, placeholders, nonScannablePostTypesSQLList()),
			args...)
		if err != nil {
			return dbVerifyQueryError()
		}
		for _, row := range rows {
			parts := strings.SplitN(row, "\t", 3)
			var content string
			if len(parts) >= 2 {
				content = parts[1]
			}
			if len(parts) >= 3 {
				content += "\n" + parts[2]
			}
			if postContentMatchesPattern(pattern, requiresExternalScript, content) {
				stillInjected++
			}
		}
	}
	if stillInjected == 0 {
		return VerifyResult{Checked: true, Resolved: true, Detail: "no affected post still contains the injected pattern"}
	}
	return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("%d affected post(s) still contain the injected pattern", stillInjected)}
}

func postContentMatchesPattern(pattern string, requiresExternalScript bool, content string) bool {
	if !strings.Contains(strings.ToLower(content), strings.ToLower(pattern)) {
		return false
	}
	if requiresExternalScript {
		return hasMaliciousExternalScriptInPost(content)
	}
	return true
}

// lookupMalwarePattern reports whether pattern is a known dbMalwarePatterns
// entry and, if so, whether it requires the external-script post-filter.
func lookupMalwarePattern(pattern string) (requiresExternalScript bool, ok bool) {
	for _, mp := range dbMalwarePatterns {
		if mp.pattern == pattern {
			return mp.requiresExternalScript, true
		}
	}
	return false, false
}

// verifyDBSpamInjection re-runs the cloaked-spam scan for the finding's keyword
// against the site's published posts and resolves when no post still matches
// (mirrors checkWPPosts' three-layer spam filter).
func verifyDBSpamInjection(message, details string) VerifyResult {
	dbName := detailField(details, "Database")
	keyword := spamKeywordFromMessage(message)
	if keyword == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the spam keyword from the finding"}
	}
	sp, ok := lookupSpamPattern(keyword)
	if !ok {
		return VerifyResult{Checked: false, Detail: "spam keyword is not auto-verifiable"}
	}
	prefixes, ok := findWPVerifyPrefixes(dbFindingAccount(message, details), dbName, details)
	if !ok {
		return dbVerifyNotLocatable("WordPress site")
	}
	var contents []string
	for _, prefix := range prefixes {
		rows, err := runDBVerifyQueryRoot(dbName,
			fmt.Sprintf("SELECT ID, post_content FROM `%sposts` WHERE post_status='publish' AND post_type NOT IN (%s) AND post_content LIKE ? LIMIT 200",
				prefix, nonScannablePostTypesSQLList()), sp.likeFragment)
		if err != nil {
			return dbVerifyQueryError()
		}
		for _, row := range rows {
			parts := strings.SplitN(row, "\t", 2)
			if len(parts) >= 2 {
				contents = append(contents, parts[1])
			}
		}
	}
	if countCloakedSpamMatches(sp, contents) == 0 {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("no published post still contains cloaked spam keyword %q", keyword)}
	}
	return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("published posts still contain cloaked spam keyword %q", keyword)}
}

var spamKeywordRe = regexp.MustCompile(`cloaked spam keyword '([^']+)'`)

func spamKeywordFromMessage(message string) string {
	m := spamKeywordRe.FindStringSubmatch(message)
	if m == nil {
		return ""
	}
	return m[1]
}

func lookupSpamPattern(keyword string) (dbSpamPattern, bool) {
	for _, sp := range dbSpamPatterns {
		if sp.keyword == keyword {
			return sp, true
		}
	}
	return dbSpamPattern{}, false
}

// parsePostIDList parses a "1, 2, 3" comma list into a deduplicated slice of
// numeric IDs. Non-numeric tokens are dropped so a malformed finding can never
// inject into the IN clause.
func parsePostIDList(s string) []string {
	if s == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" || !isAllDigits(tok) || seen[tok] {
			continue
		}
		seen[tok] = true
		out = append(out, tok)
	}
	return out
}

// inClausePlaceholders builds a "?,?,?" fragment and the matching []any args
// for a parameterized IN clause.
func inClausePlaceholders(values []string) (string, []any) {
	ph := make([]string, len(values))
	args := make([]any, len(values))
	for i, v := range values {
		ph[i] = "?"
		args[i] = v
	}
	return strings.Join(ph, ","), args
}
