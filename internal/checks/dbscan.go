package checks

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mysqlclient"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
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

// nonDocRootDirs are common account-data directories that are never candidate
// document roots during the home-directory walk. "www" is deliberately absent:
// where it is cPanel's alias for public_html the discovery walk collapses the
// symlink (canonicalWPInstallPath), and where it is a real directory it is a
// document root serving a real site.
var nonDocRootDirs = map[string]bool{
	"mail": true, "etc": true, "logs": true, "ssl": true, "tmp": true,
	"public_ftp": true, "cache": true, ".cagefs": true,
	"access-logs": true, "access_logs": true, "backups": true,
	"cgi-bin": true, "perl5": true, "spamassassin": true, "var": true,
}

// servedState records whether the panel currently serves a document root.
// A dormant install is not harmless -- it holds a live database and becomes
// public again the moment the domain is re-pointed -- but it is not being
// served to anyone today, and triage that cannot tell the two apart orders its
// queue wrongly in both directions.
type servedState int

const (
	// servedUnknown is the honest answer when the panel's domain map could not
	// be read. It is not "not served".
	servedUnknown servedState = iota
	servedByPanel
	notServed
)

// wpConfigPaths returns direct wp-config.php files at account document roots,
// each with whether the panel currently serves that root.
func wpConfigPaths(ctx context.Context) ([]string, map[string]servedState) {
	paths, served, _ := wpConfigPathsWithDomains(ctx)
	return paths, served
}

// wpConfigPathsWithDomains projects the shared install seam into the shapes
// CheckDatabaseContent works in. Discovery itself lives in wpinstalls.go, so
// this check, the object and overlap scanners, the core verifier and every
// fixer see the same installs.
func wpConfigPathsWithDomains(ctx context.Context) ([]string, map[string]servedState, map[string][]string) {
	installs, panelDomains := wpInstallsWithDomains(ctx, "db_content")
	paths := make([]string, 0, len(installs))
	served := make(map[string]servedState, len(installs))
	for _, in := range installs {
		paths = append(paths, in.ConfigPath)
		served[in.ConfigPath] = in.Served
	}
	return paths, served, panelDomains
}

// wpConfigOwners maps each discovered wp-config.php to the hosting account
// discovery attributed it to; unattributable installs are absent so their
// findings stay unstamped.
func wpConfigOwners(installs []wpInstall) map[string]string {
	owners := make(map[string]string, len(installs))
	for _, in := range installs {
		if in.Account != "" {
			owners[in.ConfigPath] = in.Account
		}
	}
	return owners
}

// The shared vhost parser omits wildcard names because they cannot be used as
// an HTTP Host for exposure probes. They still declare a served document root
// and tenant ownership, so the database scan parses those rows separately.
func parseWildcardUserdataDomainRootsChecked(content string) ([]vhost, bool) {
	var out []vhost
	complete := true
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "*.") {
			continue
		}
		parsed, lineComplete := parseUserdataDomainRootsChecked(strings.TrimPrefix(line, "*.") + "\n")
		if !lineComplete || len(parsed) != 1 {
			complete = false
			continue
		}
		parsed[0].domain = "*." + parsed[0].domain
		out = append(out, parsed[0])
	}
	return out, complete
}

func docrootBelongsToCPanelUser(root, user string) bool {
	parts := strings.Split(filepath.Clean(root), string(filepath.Separator))
	for i, part := range parts {
		if !isCPanelHomeBase(part) || i+2 >= len(parts) || parts[i+1] != user {
			continue
		}
		return true
	}
	return false
}

func isCPanelHomeBase(name string) bool {
	if name == "home" {
		return true
	}
	if !strings.HasPrefix(name, "home") || len(name) == len("home") {
		return false
	}
	for _, r := range name[len("home"):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

const maxWPSecondaryBlogs = 100

// dbSpamSampleLimit bounds the rows pulled back per spam pattern. When a
// pattern fills it, the reported count is a floor rather than a total.
const dbSpamSampleLimit = 200

func spamCountLabel(n int, truncated bool) string {
	if truncated {
		return fmt.Sprintf("at least %d", n)
	}
	return strconv.Itoa(n)
}

// dbScanCoverage counts why discovered installs could not be inspected and
// keeps one example path per reason. Multisite limits have their own detailed
// findings and are not counted again here.
//
// The owner remains incomplete when any install fails. Independently
// completed database scopes can still retire their own previous findings.
type dbScanCoverage struct {
	discovered           int
	discoveryIncomplete  bool
	counts               map[string]int
	examples             map[string]string
	queryFailures        map[string]int
	queryFailureOverflow int
}

func (c *dbScanCoverage) record(reason, configPath string) {
	if c == nil {
		return
	}
	if c.counts == nil {
		c.counts = make(map[string]int, 5)
		c.examples = make(map[string]string, 5)
	}
	c.counts[reason]++
	if c.examples[reason] == "" {
		c.examples[reason] = configPath
	}
}

func (c *dbScanCoverage) skipped() int {
	if c == nil {
		return 0
	}
	var n int
	for _, v := range c.counts {
		n += v
	}
	return n
}

// summary renders the reason breakdown, or the empty string when nothing was
// attributed, including when discovery stops before reaching any install.
func (c *dbScanCoverage) summary() string {
	if c.skipped() == 0 {
		return ""
	}
	reasons := make([]string, 0, len(c.counts))
	for reason := range c.counts {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	var b strings.Builder
	fmt.Fprintf(&b, "%d of %d discovered installs could not be fully inspected.\n", c.skipped(), c.discovered)
	for _, reason := range reasons {
		// Account-controlled names must not forge reason lines or terminal
		// commands. Bound the escaped display so expansion cannot grow it.
		example := strconv.QuoteToASCII(c.examples[reason])
		example = truncateDB(example[1:len(example)-1], 200)
		fmt.Fprintf(&b, "%s=%d (example: %s)\n", reason, c.counts[reason], example)
	}
	b.WriteString(c.queryFailureSummary())
	if c.discoveryIncomplete {
		b.WriteString("Document-root discovery was incomplete; additional installs may be missing.\n")
	}
	return b.String()
}

// CheckDatabaseContent scans WordPress databases for injected malware,
// spam content, siteurl hijacking, and rogue admin accounts.
func CheckDatabaseContent(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	coverage := &dbScanCoverage{}
	installs, panelDomains := wpInstallsWithDomains(ctx, "db_content")
	coverage.discoveryIncomplete = checkMarkedIncomplete(ctx, "db_content")
	if len(installs) == 0 {
		return appendDatabaseScanIncompleteFinding(ctx, nil, coverage)
	}
	coverage.discovered = len(installs)
	wpConfigs := make([]string, 0, len(installs))
	servedRoots := make(map[string]servedState, len(installs))
	for _, in := range installs {
		wpConfigs = append(wpConfigs, in.ConfigPath)
		servedRoots[in.ConfigPath] = in.Served
	}
	owners := wpConfigOwners(installs)
	domainOwnership := newPanelDomainOwnership(panelDomains)

	// Cache the coverage outcome as well as the scan: aliases of an unreadable
	// database are affected installs too, but must not repeat its queries.
	seenDatabases := make(map[string]string, len(wpConfigs))
	completedScopes := make(map[string]bool)
	for _, wpConfig := range wpConfigs {
		if ctx.Err() != nil {
			return findings
		}
		user := wpConfigUser(filepath.Dir(wpConfig))
		creds, complete := parseWPConfigChecked(wpConfig)
		if !complete {
			coverage.record("unreadable_config", wpConfig)
			markCheckIncomplete(ctx, "db_content")
			continue
		}
		if creds.dbName == "" || creds.dbUser == "" {
			// A missing login does not erase an otherwise known scope. Its
			// healthy alias must not retire findings this install could not
			// examine, regardless of which config discovery returned first.
			if prefix, ok := resolveTablePrefix(creds); creds.dbName != "" && ok {
				completedScopes[dbContentDedupKey(user, creds, prefix)] = false
			}
			coverage.record("missing_credentials", wpConfig)
			markCheckIncomplete(ctx, "db_content")
			continue
		}
		prefix, ok := resolveTablePrefix(creds)
		if !ok {
			coverage.record("unresolved_table_prefix", wpConfig)
			markCheckIncomplete(ctx, "db_content")
			continue
		}
		creds.tablePrefix = prefix
		creds.docrootServed = servedRoots[wpConfig]
		creds.panelDomains = domainOwnership
		databaseKey := strings.Join([]string{
			user, creds.dbHost, creds.dbName, creds.dbUser, creds.dbPass, prefix,
			strconv.FormatBool(creds.multisite),
		}, "\x00")
		if reason, duplicate := seenDatabases[databaseKey]; duplicate {
			if reason != "" {
				coverage.record(reason, wpConfig)
			}
			continue
		}
		// Isolate content-read gaps so an earlier install's failure cannot
		// mask this one's. The scanner keeps the outer context for multisite
		// limits, which already emit a separate account-specific finding.
		queryCtx, contentIncomplete := withIncompleteCheckCollector(ctx)
		creds.queryCtx = queryCtx
		creds.queryState = new(dbQueryState)
		// Stamp each install's own slice before merging: the host-wide
		// summary appended below must never inherit an owner.
		installFindings := capPhantomAuthorFindings(wpInstallScanner(ctx, user, creds, prefix), maxPhantomAuthorsReported)
		scope := dbContentDedupKey(user, creds, prefix)
		multisiteLimited := false
		for i := range installFindings {
			installFindings[i].CoverageScope = scope
			if installFindings[i].Check == "db_content_scan_incomplete" {
				multisiteLimited = true
			}
		}
		findings = append(findings, stampTenantIDIfEmpty(installFindings, owners[wpConfig])...)
		var reason string
		if creds.queryState.failed {
			reason = "query_failed"
		} else if contentIncomplete.contains("db_content") {
			reason = "incomplete_content"
		}
		scopeComplete := reason == "" && !multisiteLimited
		if prior, seen := completedScopes[scope]; seen {
			scopeComplete = scopeComplete && prior
		}
		completedScopes[scope] = scopeComplete
		coverage.recordQueryFailures(creds.queryState)
		seenDatabases[databaseKey] = reason
		if reason != "" {
			coverage.record(reason, wpConfig)
			markCheckIncomplete(ctx, "db_content")
		}
	}

	recordCompletedCoverageScopes(ctx, "db_content", completedScopes)
	return appendDatabaseScanIncompleteFinding(ctx, findings, coverage)
}

// wpInstallScanner is the per-install scan boundary. Tests replace it with
// an inert scanner to prove ownership stamping for every finding name
// without driving each SQL scanner.
var wpInstallScanner = scanWPInstall

// scanWPInstall runs every content, user and multisite scanner for one
// discovered install and returns the unstamped findings.
func scanWPInstall(ctx context.Context, user string, creds wpDBCreds, prefix string) []alert.Finding {
	var installFindings []alert.Finding

	// Always scan the main-site (or single-site) tables. In
	// multisite, blog ID 1 keeps the unprefixed names; in a
	// single-site install these are the only tables.
	installFindings = append(installFindings, scanWPBlog(user, creds, prefix, prefix)...)

	// wp_users / wp_usermeta are network-wide in multisite, so
	// the user-table scan runs once regardless of the layout.
	installFindings = append(installFindings, checkWPUsers(user, creds.withQueryStage("users"), prefix)...)

	// Multisite: enumerate active secondary blog IDs and scan
	// each one's wp_<N>_options / wp_<N>_posts. Spam, archived,
	// and deleted blogs are excluded -- their content is
	// already operator-suppressed at the WP level, and most
	// hosts have stale ones we'd otherwise alert on
	// indefinitely.
	if creds.multisite {
		installFindings = append(installFindings, scanMultisiteSecondaryBlogs(ctx, user, creds, prefix)...)
	}
	return installFindings
}

// scanWPBlog runs checks whose tables belong to one blog. usersPrefix stays
// separate because multisite blogs share the network-wide users table.
func scanWPBlog(user string, creds wpDBCreds, sitePrefix, usersPrefix string) []alert.Finding {
	var findings []alert.Finding
	findings = append(findings, checkWPOptions(user, creds.withQueryStage("options"), sitePrefix)...)
	findings = append(findings, checkWPPosts(user, creds.withQueryStage("posts"), sitePrefix)...)
	findings = append(findings, checkWPStoredCode(user, creds.withQueryStage("stored_code"), sitePrefix)...)
	findings = append(findings, checkWPSpamTaxonomy(user, creds.withQueryStage("taxonomy"), sitePrefix)...)
	findings = append(findings, checkWPHiddenLinks(user, creds.withQueryStage("hidden_links"), sitePrefix)...)
	findings = append(findings, checkWPCloakConfig(user, creds.withQueryStage("cloak_config"), sitePrefix)...)
	// Rate change rather than vocabulary: the next kit will use different
	// words, but it will still publish a flood onto a long-quiet site.
	findings = append(findings, checkWPPostVolumeBurst(user, creds.withQueryStage("post_burst"), sitePrefix)...)
	findings = append(findings,
		checkWPPhantomAuthors(user, creds.withQueryStage("phantom_authors"), sitePrefix, usersPrefix, maxPhantomAuthorsReported)...)
	return findings
}

func wpConfigUser(path string) string {
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	for i, part := range parts {
		if isCPanelHomeBase(part) && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return extractUser(path)
}

func appendDatabaseScanIncompleteFinding(ctx context.Context, findings []alert.Finding, coverage *dbScanCoverage) []alert.Finding {
	if !checkMarkedIncomplete(ctx, "db_content") {
		return findings
	}
	// A multisite-limit warning covers only its own network. Suppress the
	// generic fallback only when no other coverage gaps need reporting.
	if coverage.skipped() == 0 && !coverage.discoveryIncomplete {
		for _, finding := range findings {
			if finding.Check == "db_content_scan_incomplete" {
				return findings
			}
		}
	}
	return append(findings, alert.Finding{
		Severity: alert.Warning,
		Check:    "db_content_scan_incomplete",
		Message:  "WordPress database scan could not inspect every discovered install",
		Details:  databaseScanIncompleteDetails(coverage),
	})
}

// databaseScanIncompleteDetails names what was skipped and why when the scan
// got far enough to attribute a cause, and falls back to the generic sentence
// when no install-specific cause was recorded.
func databaseScanIncompleteDetails(coverage *dbScanCoverage) string {
	const retained = "Findings without complete database coverage are retained."
	if summary := coverage.summary(); summary != "" {
		return summary + retained
	}
	return "A document-root record, wp-config.php file, or database query could not be read safely. " + retained
}

// scanMultisiteSecondaryBlogs queries wp_blogs for active blog IDs other than 1
// and runs the per-blog scans against each. The user-table scan does not
// iterate because WP shares wp_users / wp_usermeta across the entire network
// by default. A site-specific user table only exists on configurations that
// override that, which we ignore here for v1. The phantom-author scan does
// iterate each posts table, but joins it to that shared users table.
//
// blog_id=1 is excluded because its tables are unprefixed and were
// already scanned by the caller.
func scanMultisiteSecondaryBlogs(ctx context.Context, user string, creds wpDBCreds, prefix string) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT blog_id FROM %sblogs WHERE archived = 0 AND deleted = 0 AND spam = 0 AND blog_id != 1 ORDER BY blog_id LIMIT %d",
		prefix, maxWPSecondaryBlogs+1,
	)
	rows := runMySQLQuery(creds.withQueryStage("multisite_discovery"), query)
	var findings []alert.Finding
	truncated := len(rows) > maxWPSecondaryBlogs
	if truncated {
		rows = rows[:maxWPSecondaryBlogs]
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			return findings
		}
		blogID := strings.TrimSpace(row)
		if blogID == "" || blogID == "1" {
			continue
		}
		// Guard against any garbage in the row -- only digits.
		if !isAllDigits(blogID) {
			markCheckIncomplete(creds.queryCtx, "db_content")
			markCheckIncomplete(ctx, "db_content")
			continue
		}
		sitePrefix := fmt.Sprintf("%s%s_", prefix, blogID)
		findings = append(findings, scanWPBlog(user, creds, sitePrefix, prefix)...)
	}
	if truncated {
		markCheckIncomplete(ctx, "db_content")
		findings = append(findings, alert.Finding{
			Severity: alert.Warning,
			Check:    "db_content_scan_incomplete",
			Message:  fmt.Sprintf("WordPress multisite database scan reached its %d-site safety limit (account: %s)", maxWPSecondaryBlogs, user),
			Details: dbContentFindingDetails(creds, prefix,
				"The network has more active secondary sites than one scheduled scan can safely inspect."),
			DedupKey: dbContentDedupKey(user, creds, prefix,
				"The network has more active secondary sites than one scheduled scan can safely inspect."),
		})
	}
	return findings
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type wpDBCreds struct {
	dbName      string
	dbUser      string
	dbPass      string
	dbHost      string
	tablePrefix string
	// docrootServed records whether the panel serves this install's document
	// root, so a finding says whether it is reachable today.
	docrootServed servedState
	// panelDomains is the complete panel domain ownership map. The foreign-host
	// check needs every account, not just this one, so a more-specific domain
	// delegated to another tenant wins over this account's parent domain.
	panelDomains *panelDomainOwnership
	// queryCtx ties scheduled database work to the runner's deadline. Command
	// paths leave it nil and retain the per-query timeout below.
	queryCtx context.Context
	// queryOwner identifies the CMS check whose coverage depends on a query.
	// WordPress callers use the default owner when this is empty.
	queryOwner string
	// queryState is shared by the sequential queries for one install.
	// Coverage failures and an unusable connection are tracked separately.
	queryState *dbQueryState
	queryStage string
	// multisite is set when wp-config.php declares
	// `define('MULTISITE', true)`. In multisite, the main blog
	// (ID 1) keeps the unprefixed table names and secondary blogs
	// live under `wp_<N>_options` / `wp_<N>_posts`. CheckDatabaseContent
	// scans both layouts when this is set; a single-site install
	// (multisite=false) skips the wp_blogs lookup and per-site
	// iteration entirely.
	multisite bool
}

// parseWPConfig extracts database credentials from wp-config.php.
func parseWPConfig(path string) wpDBCreds {
	creds, complete := parseWPConfigChecked(path)
	if !complete {
		return wpDBCreds{}
	}
	return creds
}

// parseWPConfigChecked bounds account-controlled input so a special or very
// large wp-config.php cannot strand the scheduled database scan.
func parseWPConfigChecked(path string) (wpDBCreds, bool) {
	f, err := openCMSConfig(path)
	if err != nil {
		return wpDBCreds{}, false
	}
	defer func() { _ = f.Close() }()

	var creds wpDBCreds
	limited := &io.LimitedReader{R: f, N: maxCMSConfigBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64*1024), maxCMSConfigBytes+1)
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

		// Match: define( 'MULTISITE', true );
		if extractDefineBool(line, "MULTISITE") {
			creds.multisite = true
		}
	}

	if creds.dbHost == "" {
		creds.dbHost = "localhost"
	}

	return creds, scanner.Err() == nil && limited.N > 0
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

// extractDefineBool returns true when line is a non-comment
// define('<key>', true) -- i.e., a bare boolean value rather than a
// quoted string. Used for `MULTISITE` and any future bool defines
// CSM cares about. Whitespace is permissive, case-insensitive on
// the literal `true`, trailing PHP/inline comments tolerated.
//
// The key must appear inside its enclosing PHP quotes (single or
// double). This avoids a substring-match collision: a WordPress
// wp-config.php commonly carries `define('WP_ALLOW_MULTISITE',
// true)` to enable the admin network creator on single-site
// installs; matching MULTISITE as a bare substring would falsely
// detect those as multisite hosts.
//
// Operators using anything other than the canonical `true` literal
// (e.g., `!false`, `1`, `defined('FOO')`) won't get multisite
// scanning. That's preferable to running an arbitrary PHP expression
// evaluator over wp-config.php.
func extractDefineBool(line, key string) bool {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") {
		return false
	}
	if !strings.Contains(trimmed, "define") {
		return false
	}

	// Find the key's quoted form and seek past the closing quote.
	// Two acceptable openings: 'KEY' and "KEY". The key never
	// appears unquoted inside a define() literal in valid PHP.
	var keyEnd int
	switch {
	case strings.Contains(trimmed, "'"+key+"'"):
		keyEnd = strings.Index(trimmed, "'"+key+"'") + len(key) + 2
	case strings.Contains(trimmed, `"`+key+`"`):
		keyEnd = strings.Index(trimmed, `"`+key+`"`) + len(key) + 2
	default:
		return false
	}

	rest := trimmed[keyEnd:]
	commaIdx := strings.Index(rest, ",")
	if commaIdx < 0 {
		return false
	}
	value := rest[commaIdx+1:]
	// The value runs until the closing paren; everything after it
	// is the statement terminator and any trailing comment.
	if closeIdx := strings.Index(value, ")"); closeIdx >= 0 {
		value = value[:closeIdx]
	}
	return strings.EqualFold(strings.TrimSpace(value), "true")
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

// runMySQLQuery executes a MySQL query via the in-process database/sql
// driver and returns each row tab-joined, matching the legacy
// `mysql -N -B -e <query>` output shape so existing tab-split callers
// keep working unchanged. Returns nil on any open / query / scan
// error (the legacy implementation swallowed errors the same way).
// Var so tests can serve canned rows without a live database.
var runMySQLQuery = func(creds wpDBCreds, query string) []string {
	if creds.queryState != nil && creds.queryState.halted {
		return nil
	}
	parent := creds.queryCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	rows, err := mysqlclient.PerAccountQuery(ctx, mysqlclient.Creds{
		User:     creds.dbUser,
		Password: creds.dbPass,
		Host:     creds.dbHost,
		DBName:   creds.dbName,
	}, query)
	if err != nil {
		creds.queryState.record(creds.queryStage, err)
		markCheckIncomplete(creds.queryCtx, creds.queryCheck())
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, line := range rows {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (c wpDBCreds) queryCheck() string {
	if c.queryOwner != "" {
		return c.queryOwner
	}
	return "db_content"
}

// siteURLPoisonReason reports why a siteurl/home value cannot be a real site
// address, and whether it is one at all. WordPress concatenates this value to
// build every asset URL it emits, so an attacker who rewrites it makes the
// address it names load on every page without touching a single file.
//
// The test is the URL's shape, not its host. Hosting a site under a domain
// that is not served locally is ordinary -- sites move, staging lives
// elsewhere, and a theme demo keeps its vendor address -- so a host check
// would report dozens of healthy installs. Shape does not have that problem:
// a site address is an origin plus an optional subdirectory. A backslash, a
// query string, a fragment, a script for a path, or a non-web scheme cannot
// appear in one.
func siteURLPoisonReason(value string) (string, bool) {
	// MySQL query rows preserve batch-mode escaping. Parse the stored bytes,
	// not the escaped transport form, or control characters can look like an
	// ordinary path and evade the shape checks below.
	value = strings.TrimSpace(mysqlclient.BatchUnescape(value))
	if value == "" {
		return "", false
	}
	if strings.ContainsRune(value, '\\') {
		return "address carries a backslash", true
	}
	u, err := url.Parse(value)
	if err != nil {
		return "value is not a URL", true
	}
	if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" {
		return "scheme is not http or https", true
	}
	if u.Hostname() == "" {
		return "no host", true
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "port is outside the valid range", true
		}
	}
	if u.RawQuery != "" || strings.Contains(value, "?") {
		return "address carries a query string", true
	}
	if u.Fragment != "" || strings.Contains(value, "#") {
		return "address carries a fragment", true
	}
	if isScriptPath(u.Path) {
		return "address resolves to a script", true
	}
	return "", false
}

// isScriptPath reports whether a URL path's final segment names a client- or
// server-side script. A site address always ends at a directory.
func isScriptPath(path string) bool {
	segment := path
	if i := strings.LastIndex(segment, "/"); i >= 0 {
		segment = segment[i+1:]
	}
	segment = strings.ToLower(segment)
	if isExecutablePHPName(segment) {
		return true
	}
	switch filepath.Ext(segment) {
	case ".js", ".mjs", ".cjs",
		".asp", ".aspx", ".ashx", ".asmx",
		".jsp", ".jspx", ".cfm",
		".cgi", ".pl", ".py", ".rb":
		return true
	default:
		return false
	}
}

// checkWPOptions checks for siteurl/home hijacking and injected JavaScript.
func checkWPOptions(user string, creds wpDBCreds, prefix string) []alert.Finding {
	var findings []alert.Finding
	foreignByOption := make(map[string]*alert.Finding, 2)

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
		// WordPress's default option_name collation is case-insensitive, so a
		// differently-cased row can satisfy get_option("siteurl") and this SQL
		// query. Keep the Go-side security check consistent with that lookup.
		optName := strings.ToLower(strings.TrimSpace(parts[0]))
		optValue := strings.ToLower(parts[1])

		if optName == "siteurl" || optName == "home" {
			if strings.Contains(optValue, "eval(") || strings.Contains(optValue, "<script") {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "db_siteurl_hijack",
					Message:  fmt.Sprintf("WordPress %s contains malicious code (account: %s)", optName, user),
					Details: dbContentFindingDetails(creds, prefix,
						fmt.Sprintf("%s = %s", optName, truncateDB(parts[1], 200))),
					DedupKey: dbContentDedupKey(user, creds, prefix,
						fmt.Sprintf("%s = %s", optName, truncateDB(parts[1], 200))),
				})
			} else if reason, bad := siteURLPoisonReason(parts[1]); bad {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "db_siteurl_invalid",
					Message:  fmt.Sprintf("WordPress %s is not a site address (account: %s): %s", optName, user, reason),
					Details: dbContentFindingDetails(creds, prefix,
						fmt.Sprintf("%s = %s\nWordPress builds every asset URL from this value, so the address it names is loaded on every page.",
							optName, truncateDB(parts[1], 200))),
					DedupKey: dbContentDedupKey(user, creds, prefix,
						"reason="+reason,
						fmt.Sprintf("%s = %s\nWordPress builds every asset URL from this value, so the address it names is loaded on every page.",
							optName, truncateDB(parts[1], 200))),
				})
			} else if foreign := foreignSiteURLFinding(user, creds, prefix, optName, parts[1]); foreign != nil {
				// siteurl and home commonly hold the same address. Emit one stable
				// condition per blog, preferring siteurl regardless of row order.
				if current := foreignByOption[optName]; current == nil || foreign.Details < current.Details {
					foreignByOption[optName] = foreign
				}
			}
		}
	}
	for _, option := range []string{"siteurl", "home"} {
		if foreign := foreignByOption[option]; foreign != nil {
			findings = append(findings, *foreign)
			break
		}
	}

	// Path 1: External script URLs in any option — only flag non-safe domains.
	query = fmt.Sprintf(
		"SELECT option_name, option_value FROM %soptions WHERE option_value LIKE '%%<script%%src%%' LIMIT 20",
		prefix)
	lines = runMySQLQuery(creds, query)
	firstSeen := storeFirstSeen(externalScriptSiteKey(creds.dbName, prefix))

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
			// No attacker marker. A loader on an unremarkable HTTPS host is
			// still reported once, the first time it appears after the
			// site's baseline.
			findings = append(findings, newExternalScriptFindings(user, creds, prefix, optName, optValue, firstSeen)...)
			continue
		}

		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "db_options_injection",
			Message:  fmt.Sprintf("Malicious script injection in wp_options '%s' (account: %s)", optName, user),
			Details: dbContentFindingDetails(creds, prefix,
				fmt.Sprintf("Option: %s", optName),
				fmt.Sprintf("Malicious URL: %s", maliciousURL),
				fmt.Sprintf("Content preview: %s", truncateDB(optValue, 200))),
			DedupKey: dbContentDedupKey(user, creds, prefix,
				fmt.Sprintf("Option: %s", optName),
				fmt.Sprintf("Malicious URL: %s", maliciousURL),
				fmt.Sprintf("Content preview: %s", truncateDB(optValue, 200))),
		})
	}
	queryComplete := creds.queryState == nil || !creds.queryState.failed
	if queryComplete {
		if sdb := store.Global(); sdb != nil {
			_ = sdb.FinishExternalScriptBaseline(externalScriptSiteKey(creds.dbName, prefix), time.Now())
		}
	}

	// Path 1b: Plugin status options that WordPress renders as admin
	// notices. These are queried by name because the generic script lookup
	// above caps its result set and requires a src attribute, while an
	// injection here may be inline. The option's identity is the verdict,
	// so neither host reputation nor the first-seen baseline applies.
	findings = append(findings, checkWPPluginNotices(user, creds, prefix)...)

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
			Details: dbContentFindingDetails(creds, prefix,
				fmt.Sprintf("Option: %s", parts[0]),
				fmt.Sprintf("Content preview: %s", truncateDB(parts[1], 200))),
			DedupKey: dbContentDedupKey(user, creds, prefix,
				fmt.Sprintf("Option: %s", parts[0]),
				fmt.Sprintf("Content preview: %s", truncateDB(parts[1], 200))),
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

	// Keep each pattern's independent LIMIT, but send the bounded selects as
	// one UNION. On a host with hundreds of installs this avoids one database
	// connection and round trip per signature without letting a noisy pattern
	// consume every candidate slot for the others.
	malwareSelects := make([]string, 0, len(dbMalwarePatterns))
	for i, mp := range dbMalwarePatterns {
		pattern := mysqlEscapeForLike(mp.pattern)
		selectedContent := "'_content_not_required'"
		if mp.requiresExternalScript {
			selectedContent = "CONCAT_WS(CHAR(10), post_content, post_content_filtered)"
		}
		malwareSelects = append(malwareSelects, fmt.Sprintf(
			"(SELECT %d AS pattern_index, ID, %s FROM %sposts WHERE post_status='publish' AND post_type NOT IN (%s) AND (post_content LIKE '%%%s%%' OR post_content_filtered LIKE '%%%s%%') LIMIT 20)",
			i, selectedContent, prefix, postTypeExcl, pattern, pattern))
	}
	malwareRows := runMySQLQuery(creds, strings.Join(malwareSelects, " UNION ALL "))
	confirmedByPattern := make([][]string, len(dbMalwarePatterns))
	seenByPattern := make([]map[string]struct{}, len(dbMalwarePatterns))
	for _, row := range malwareRows {
		parts := strings.SplitN(row, "\t", 3)
		if len(parts) != 3 {
			continue
		}
		patternIndex, err := strconv.Atoi(parts[0])
		if err != nil || patternIndex < 0 || patternIndex >= len(dbMalwarePatterns) {
			continue
		}
		mp := dbMalwarePatterns[patternIndex]
		content := mysqlclient.BatchUnescape(parts[2])
		if mp.requiresExternalScript && !hasMaliciousExternalScriptInPost(content) {
			continue
		}
		if seenByPattern[patternIndex] == nil {
			seenByPattern[patternIndex] = make(map[string]struct{})
		}
		postID := strings.TrimSpace(parts[1])
		if postID == "" {
			continue
		}
		if _, duplicate := seenByPattern[patternIndex][postID]; duplicate {
			continue
		}
		seenByPattern[patternIndex][postID] = struct{}{}
		if len(confirmedByPattern[patternIndex]) < 5 {
			confirmedByPattern[patternIndex] = append(confirmedByPattern[patternIndex], postID)
		}
	}
	for i, confirmedIDs := range confirmedByPattern {
		if len(confirmedIDs) == 0 {
			continue
		}
		mp := dbMalwarePatterns[i]
		findings = append(findings, alert.Finding{
			Severity: mp.severity,
			Check:    "db_post_injection",
			Message:  fmt.Sprintf("WordPress posts contain %s (account: %s, %d posts)", mp.desc, user, len(confirmedIDs)),
			Details: dbContentFindingDetails(creds, prefix,
				fmt.Sprintf("Affected post IDs: %s", strings.Join(confirmedIDs, ", ")),
				fmt.Sprintf("Pattern: %s", mp.pattern)),
			DedupKey: dbContentDedupKey(user, creds, prefix,
				fmt.Sprintf("Affected post IDs: %s", strings.Join(confirmedIDs, ", ")),
				fmt.Sprintf("Pattern: %s", mp.pattern)),
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
	spamSelects := make([]string, 0, len(dbSpamPatterns))
	for i, sp := range dbSpamPatterns {
		spamSelects = append(spamSelects, fmt.Sprintf(
			"(SELECT %d AS pattern_index, ID, post_content FROM %sposts WHERE post_status='publish' AND post_type NOT IN (%s) AND post_content LIKE '%s' LIMIT %d)",
			i, prefix, postTypeExcl, mysqlEscapeForLike(sp.likeFragment), dbSpamSampleLimit))
	}
	spamRows := runMySQLQuery(creds, strings.Join(spamSelects, " UNION ALL "))
	spamContents := make([][]string, len(dbSpamPatterns))
	spamSampled := make([]int, len(dbSpamPatterns))
	for _, row := range spamRows {
		parts := strings.SplitN(row, "\t", 3)
		patternIndex, err := strconv.Atoi(parts[0])
		if err != nil || patternIndex < 0 || patternIndex >= len(dbSpamPatterns) {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		spamSampled[patternIndex]++
		if len(parts) != 3 {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		spamContents[patternIndex] = append(spamContents[patternIndex], mysqlclient.BatchUnescape(parts[2]))
	}
	for i, sp := range dbSpamPatterns {
		n := countCloakedSpamMatches(sp, spamContents[i])
		if n == 0 {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "db_spam_injection",
			// The per-pattern LIMIT bounds the sample, so a full sample means
			// the real figure may be larger. Reporting it as exact understates the
			// scale, and scale is what decides whether an operator looks.
			Message: fmt.Sprintf("WordPress posts contain cloaked spam keyword '%s' (%s posts, account: %s)",
				sp.keyword, spamCountLabel(n, spamSampled[i] >= dbSpamSampleLimit), user),
			Details: dbContentFindingDetails(creds, prefix),
			// The pattern is the identity; the count is not. Spam grows between
			// scans, and that is the same finding, not a new one.
			DedupKey: dbContentDedupKey(user, creds, prefix, "keyword="+sp.keyword),
		})
	}

	return findings
}

// dbContentDedupKey pins a database-content finding's identity to the database
// it was found in, the account using it, and what was found there. Callers
// include stable distinctions from Message as well as Details, excluding
// observation-only changes such as site age and document-root served state.
//
// The document-root note is deliberately excluded. It reports what the panel's
// domain map said during this scan, not anything the scan found in the
// database, and that map read fails transiently -- when it does the note
// disappears, the default Message+Details identity changes with it, and the
// store keeps a second copy of a finding that never changed.
func dbContentDedupKey(user string, creds wpDBCreds, prefix string, lines ...string) string {
	identity := make([]byte, 0, 128)
	appendField := func(value string) {
		identity = binary.BigEndian.AppendUint64(identity, uint64(len(value)))
		identity = append(identity, value...)
	}
	appendField(user)
	appendField(creds.dbHost)
	appendField(creds.dbName)
	appendField(prefix)
	for _, line := range lines {
		appendField(line)
	}
	digest := sha256.Sum256(identity)
	return fmt.Sprintf("db-content:%x", digest[:12])
}

// dbContentFindingDetails renders a database-content finding's details. The
// document-root note it adds is scan-time context, not part of what was found,
// so every caller supplies a DedupKey that excludes this note.
func dbContentFindingDetails(creds wpDBCreds, prefix string, lines ...string) string {
	out := []string{
		fmt.Sprintf("Database: %s", creds.dbName),
		fmt.Sprintf("Table prefix: %s", prefix),
	}
	if note := docrootServedNote(creds.docrootServed); note != "" {
		out = append(out, note)
	}
	out = append(out, lines...)
	return strings.Join(out, "\n")
}

// wpInstallAdminGrace is how far after the first user registration an
// admin account still counts as created by the site install itself.
// Softaculous and similar installers register the initial admin (and any
// setup-wizard co-admins) within moments of creating the users table, so
// those accounts are the install, not a takeover. Anything later is a
// change to an existing site and stays alert-worthy.
const wpInstallAdminGrace = 15 * time.Minute

const wpRegisteredLayout = "2006-01-02 15:04:05"

func parseWPRegistered(value string) (time.Time, error) {
	return time.Parse(wpRegisteredLayout, strings.TrimSpace(value))
}

// wpInstallEraAdmin reports whether an admin registration timestamp falls
// within the install grace of the site's first user registration. Fails
// open: unparseable timestamps never suppress.
func wpInstallEraAdmin(registered, firstRegistered string) bool {
	reg, err := parseWPRegistered(registered)
	if err != nil {
		return false
	}
	first, err := parseWPRegistered(firstRegistered)
	if err != nil {
		return false
	}
	diff := reg.Sub(first)
	return diff >= 0 && diff <= wpInstallAdminGrace
}

// checkWPUsers checks for rogue admin accounts created recently.
func checkWPUsers(user string, creds wpDBCreds, prefix string) []alert.Finding {
	var findings []alert.Finding

	// Find admin users created in the last 7 days. Missing registration
	// timestamps stay in scope so the suppression fails open.
	// MIN(user_registered) rides along as the install marker, but any NULL
	// invalidates that marker. EXISTS keeps duplicate capability metadata
	// from consuming the bounded result.
	query := fmt.Sprintf(
		"SELECT u.ID, u.user_login, u.user_email, u.user_registered, "+
			"(SELECT CASE WHEN COUNT(*) <> COUNT(user_registered) "+
			"THEN NULL ELSE MIN(user_registered) END FROM %susers) FROM %susers u "+
			"WHERE EXISTS (SELECT 1 FROM %susermeta m "+
			"WHERE m.user_id = u.ID AND m.meta_key = '%scapabilities' "+
			"AND m.meta_value LIKE '%%administrator%%') "+
			"AND (u.user_registered >= DATE_SUB(NOW(), INTERVAL 7 DAY) "+
			"OR u.user_registered IS NULL "+
			"OR CAST(u.user_registered AS CHAR) = '0000-00-00 00:00:00') "+
			"ORDER BY (u.user_registered IS NULL OR "+
			"CAST(u.user_registered AS CHAR) = '0000-00-00 00:00:00') DESC, "+
			"u.user_registered DESC "+
			"LIMIT 10",
		prefix, prefix, prefix, prefix)
	lines := runMySQLQuery(creds, query)

	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 5)
		if len(parts) < 3 {
			continue
		}
		if wpInstallEraAdmin(safeGet(parts, 3), safeGet(parts, 4)) {
			continue
		}
		registered := safeGet(parts, 3)
		message := fmt.Sprintf("New WordPress admin account created in last 7 days: %s (account: %s)", parts[1], user)
		if _, err := parseWPRegistered(registered); err != nil {
			message = fmt.Sprintf("WordPress admin account has a missing or invalid registration timestamp: %s (account: %s)", parts[1], user)
		}

		severity := alert.Critical
		details := fmt.Sprintf("Database: %s\nTable prefix: %s\nUser ID: %s\nLogin: %s\nEmail: %s\nRegistered: %s",
			creds.dbName, prefix, parts[0], parts[1], parts[2], registered)

		// A stable session pattern can support the legitimate developer or agency
		// case, but session metadata is not authoritative. Downgrade -- never
		// suppress -- so a forged session record cannot hide the account.
		loginIPs := wpAdminLoginIPs(creds, prefix, parts[0])
		distinct := uniqueStrings(loginIPs)
		switch {
		case len(loginIPs) == 0:
			details += "\nSession-token IP evidence: none recorded."
		case len(loginIPs) >= wpEstablishedLoginSessions && len(distinct) == 1:
			severity = alert.Warning
			details += fmt.Sprintf("\nSession-token IP evidence: %d stored sessions from a single IP (%s) -- consistent with a stable operator login pattern, but not proof the account is legitimate. Verify with the account owner before acting.",
				len(loginIPs), distinct[0])
		default:
			details += fmt.Sprintf("\nSession-token IP evidence: %d stored sessions from %d IP(s): %s",
				len(loginIPs), len(distinct), strings.Join(firstN(distinct, 5), ", "))
		}

		findings = append(findings, alert.Finding{
			Severity: severity,
			Check:    "db_rogue_admin",
			Message:  message,
			Details:  details,
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
					Details:  fmt.Sprintf("Database: %s\nTable prefix: %s\nEmail: %s", creds.dbName, prefix, email),
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

	wpConfigs := spamCleanWPConfigs(account)

	for _, wpConfig := range wpConfigs {
		creds := parseWPConfig(wpConfig)
		if creds.dbName == "" {
			continue
		}
		prefix, ok := resolveTablePrefix(creds)
		if !ok {
			continue
		}
		creds.tablePrefix = prefix

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

// wpEstablishedLoginSessions is the number of stored login sessions from a
// single stable IP that is strong enough to downgrade the finding for review.
const wpEstablishedLoginSessions = 5

// parseSessionTokenIPs extracts structurally valid login source IPs from a
// WordPress session_tokens usermeta blob in session order.
func parseSessionTokenIPs(serialized string) []string {
	var ips []string
	for i := 0; i < len(serialized); {
		key, next, ok := parsePHPSerializedStringAt(serialized, i)
		if !ok {
			if serialized[i] == 's' && i+1 < len(serialized) && serialized[i+1] == ':' {
				return nil
			}
			i++
			continue
		}
		if key != "ip" {
			i = next
			continue
		}

		value, afterValue, ok := parsePHPSerializedStringAt(serialized, next)
		if !ok {
			return nil
		}
		addr, err := netip.ParseAddr(value)
		if err == nil {
			ips = append(ips, addr.Unmap().String())
		}
		i = afterValue
	}
	return ips
}

// parsePHPSerializedStringAt reads one PHP s:<length>:"<value>"; token. Using
// the declared byte length prevents a forged token-looking fragment inside a
// session's attacker-controlled user-agent string from being treated as a key.
func parsePHPSerializedStringAt(serialized string, start int) (string, int, bool) {
	if start < 0 || start+2 > len(serialized) ||
		serialized[start] != 's' || serialized[start+1] != ':' {
		return "", start, false
	}

	lengthStart := start + 2
	lengthEnd := lengthStart
	for lengthEnd < len(serialized) &&
		serialized[lengthEnd] >= '0' && serialized[lengthEnd] <= '9' {
		lengthEnd++
	}
	if lengthEnd == lengthStart || lengthEnd+2 > len(serialized) ||
		serialized[lengthEnd] != ':' || serialized[lengthEnd+1] != '"' {
		return "", start, false
	}

	valueLen, err := strconv.Atoi(serialized[lengthStart:lengthEnd])
	if err != nil {
		return "", start, false
	}
	valueStart := lengthEnd + 2
	if valueLen > len(serialized)-valueStart {
		return "", start, false
	}
	valueEnd := valueStart + valueLen
	if valueEnd+2 > len(serialized) ||
		serialized[valueEnd] != '"' || serialized[valueEnd+1] != ';' {
		return "", start, false
	}
	return serialized[valueStart:valueEnd], valueEnd + 2, true
}

// wpAdminLoginIPs returns source IPs encoded in an admin's stored login
// sessions. The caller treats this forgeable metadata only as downgrade
// evidence and never uses it to suppress the finding.
func wpAdminLoginIPs(creds wpDBCreds, prefix, userID string) []string {
	if !wpNumericID(userID) {
		return nil
	}
	q := fmt.Sprintf(
		"SELECT meta_value FROM %susermeta WHERE user_id = %s AND meta_key = 'session_tokens' LIMIT 1",
		prefix, userID)
	serialized := mysqlclient.BatchUnescape(strings.Join(runMySQLQuery(creds, q), ""))
	return parseSessionTokenIPs(serialized)
}

// wpNumericID guards the user id (a prior query row value) before it is
// interpolated into the session lookup.
func wpNumericID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// firstN caps a slice for display in finding details.
func firstN(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

// docrootServedNote states whether this install is reachable today. Both
// answers change how a finding should be queued: a dormant install is not
// serving anyone right now, and a served one is. Silence when the panel's map
// could not be read -- claiming either would be a guess.
func docrootServedNote(state servedState) string {
	switch state {
	case servedByPanel:
		return "Document root: served by the panel, so this is live now."
	case notServed:
		return "Document root: not currently served. The database is still live " +
			"and the content publishes again the moment a domain is pointed here."
	default:
		return ""
	}
}

// spamCleanWPConfigs lists the installs the spam cleaner acts on. Shared
// discovery: spam left in a nested or panel-mapped install is the same spam.
func spamCleanWPConfigs(account string) []string {
	return wpInstallConfigPaths(wpInstallsForAccount(context.Background(), "db_content", account))
}
