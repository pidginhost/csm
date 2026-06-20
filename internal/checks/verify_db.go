package checks

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// Per-finding Re-check for the database-content family (Phase C3).
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
var validAccountName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// messageAccountRe pulls the account out of a "(account: <user>)" suffix that
// the WordPress content findings carry in their message.
var messageAccountRe = regexp.MustCompile(`account:\s*([^,)]+)`)

// detailField returns the value of a "Key: value" line in a finding's Details
// block, or "" when the key is absent. The key match is case-sensitive and the
// value is whitespace-trimmed.
func detailField(details, key string) string {
	want := key + ":"
	for _, line := range strings.Split(details, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, want) {
			return strings.TrimSpace(line[len(want):])
		}
	}
	return ""
}

// dbFindingAccount resolves the cPanel account a database finding belongs to.
// CMS, DB-object, and admin findings carry it as an "Account:" detail line; the
// WordPress content findings carry it only in the message "(account: <user>)".
func dbFindingAccount(message, details string) string {
	if a := detailField(details, "Account"); a != "" {
		return a
	}
	if m := messageAccountRe.FindStringSubmatch(message); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
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

// findWPVerifyCreds re-discovers the WordPress install for account whose
// database matches dbName, returning the validated table prefix. Uses the same
// /home/<account> globs as the detector. ok=false when nothing matches so the
// caller refuses to guess against the wrong database.
func findWPVerifyCreds(account, dbName string) (prefix string, ok bool) {
	if !validAccountName.MatchString(account) || dbName == "" {
		return "", false
	}
	patterns := []string{fmt.Sprintf("/home/%s/public_html/wp-config.php", account)}
	addon, _ := osFS.Glob(fmt.Sprintf("/home/%s/*/wp-config.php", account))
	patterns = append(patterns, addon...)

	for _, path := range patterns {
		creds := parseWPConfig(path)
		if creds.dbName != dbName {
			continue
		}
		p, ok := resolveTablePrefix(creds)
		if !ok {
			return "", false
		}
		return p, true
	}
	return "", false
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
	prefix, ok := findWPVerifyCreds(dbFindingAccount(message, details), dbName)
	if !ok {
		return dbVerifyNotLocatable("WordPress site")
	}
	rows, err := runDBVerifyQueryRoot(dbName,
		fmt.Sprintf("SELECT option_value FROM `%soptions` WHERE option_name = ?", prefix), optName)
	if err != nil {
		return dbVerifyQueryError()
	}
	if len(rows) == 0 {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("option %q is no longer present", optName)}
	}
	if optionValueStillMalicious(optName, rows[0]) {
		return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("option %q still contains injected content", optName)}
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
	prefix, ok := findWPVerifyCreds(dbFindingAccount(message, details), dbName)
	if !ok {
		return dbVerifyNotLocatable("WordPress site")
	}
	rows, err := runDBVerifyQueryRoot(dbName,
		fmt.Sprintf("SELECT option_value FROM `%soptions` WHERE option_name = ?", prefix), optName)
	if err != nil {
		return dbVerifyQueryError()
	}
	if len(rows) == 0 {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("option %q is no longer present", optName)}
	}
	lower := strings.ToLower(rows[0])
	if strings.Contains(lower, "eval(") || strings.Contains(lower, "<script") {
		return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("option %q still contains malicious code", optName)}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("option %q no longer contains malicious code", optName)}
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

// verifyDBPostInjection re-reads the affected posts and resolves the finding
// when none of them still match the injected pattern (mirrors checkWPPosts'
// per-pattern external-script post-filter). A post that was deleted simply does
// not return a row; a post that is still injected -- published or not -- keeps
// the finding active, which is the conservative choice.
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
	prefix, ok := findWPVerifyCreds(dbFindingAccount(message, details), dbName)
	if !ok {
		return dbVerifyNotLocatable("WordPress site")
	}
	placeholders, args := inClausePlaceholders(ids)
	rows, err := runDBVerifyQueryRoot(dbName,
		fmt.Sprintf("SELECT ID, post_content, post_content_filtered FROM `%sposts` WHERE ID IN (%s)", prefix, placeholders),
		args...)
	if err != nil {
		return dbVerifyQueryError()
	}
	stillInjected := 0
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
	prefix, ok := findWPVerifyCreds(dbFindingAccount(message, details), dbName)
	if !ok {
		return dbVerifyNotLocatable("WordPress site")
	}
	rows, err := runDBVerifyQueryRoot(dbName,
		fmt.Sprintf("SELECT ID, post_content FROM `%sposts` WHERE post_status='publish' AND post_type NOT IN (%s) AND post_content LIKE ? LIMIT 200",
			prefix, nonScannablePostTypesSQLList()), sp.likeFragment)
	if err != nil {
		return dbVerifyQueryError()
	}
	contents := make([]string, 0, len(rows))
	for _, row := range rows {
		parts := strings.SplitN(row, "\t", 2)
		if len(parts) >= 2 {
			contents = append(contents, parts[1])
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
