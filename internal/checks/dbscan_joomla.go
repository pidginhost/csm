package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// Joomla database content scanner.
//
// Discovery: glob /home/*/public_html/configuration.php and
// verify the file contains `class JConfig` -- the canonical marker
// for a Joomla site, distinguishing it from PHP files that happen
// to share the configuration.php filename. Credentials are read
// via regex over public-property assignments (`public $host = ...;`)
// rather than PHP eval; the parser ignores anything outside the
// JConfig class body.
//
// Scanned tables (all prefixed; the prefix is operator-controlled
// via configuration.php's $dbprefix and defaults to `jos_` /
// `<random>_` on fresh installs):
//
//   <prefix>extensions    params blob -- live_site, sitename,
//                         offline_message are common hijack targets
//   <prefix>content       article body for malware patterns
//   <prefix>users         user table; joined with
//   <prefix>user_usergroup_map  to find rogue Super Users
//                         (group_id = 8 in vanilla Joomla)
//
// Three new finding categories. CMS-explicit names so operators
// running mixed-CMS hosts can suppress per-CMS:
//
//   joomla_extensions_injection  (Critical) -- malware pattern in
//                                              an extension's params
//   joomla_content_injection     (Critical) -- malware pattern in
//                                              an article body
//   joomla_admin_injection       (Critical) -- rogue Super User
//                                              account

// jConfigCredsPattern parses a `public $foo = 'value';` line
// (single OR double quotes). Anchored to the start of the line so
// arbitrary text inside string literals further along can't be
// misread as a credential.
var jConfigCredsPattern = regexp.MustCompile(`^\s*public\s+\$(\w+)\s*=\s*['"]([^'"]*)['"]\s*;`)

// joomlaSuperUserGroupID is the canonical group id for "Super Users"
// in vanilla Joomla 3+. Operators on hardened installs may have
// renumbered; the spec narrows to 8 for v1.
const joomlaSuperUserGroupID = 8

// jConfigCreds carries the credentials extracted from a Joomla
// configuration.php. Mirrors the wpDBCreds shape so the existing
// runMySQLQuery / mysqlSchemaLiteral helpers can be reused, but
// kept distinct because Joomla configuration.php and WordPress
// wp-config.php are not interchangeable.
type jConfigCreds struct {
	// ctx ties every query for this install to the runner's deadline.
	ctx        context.Context
	dbName     string
	dbUser     string
	dbPass     string
	dbHost     string
	dbPrefix   string
	path       string
	queryState *dbQueryState
}

// asWPDBCreds returns the equivalent wpDBCreds for runMySQLQuery
// reuse. The `multisite` field is irrelevant here; the existing
// mysql client wrapper does not look at it.
func (c jConfigCreds) asWPDBCreds() wpDBCreds {
	return wpDBCreds{
		dbName:      c.dbName,
		dbUser:      c.dbUser,
		dbPass:      c.dbPass,
		dbHost:      c.dbHost,
		tablePrefix: c.dbPrefix,
		queryCtx:    c.ctx,
		queryOwner:  "db_content_joomla",
		queryState:  c.queryState,
	}
}

// CheckJoomlaContent scans every Joomla installation under
// /home/*/public_html for malware-pattern matches in the three
// canonical attacker-touched tables. Mirrors the structure of
// CheckDatabaseContent without sharing code -- the credentials and
// table layout differ enough that a generic dispatcher is more
// abstraction than this point in the codebase needs.
func CheckJoomlaContent(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}
	var findings []alert.Finding

	configs := cmsDiscover(ctx, "db_content_joomla", "*/public_html/configuration.php", "*/*/configuration.php")
	if len(configs) == 0 {
		return nil
	}

	// Rank by mtime desc so recently touched Joomla installs are processed
	// first when the check timeout cuts iteration short.
	for _, path := range rankCMSConfigs(ctx, "db_content_joomla", configs, accountScanMaxFiles(ctx, cfg)) {
		if ctx.Err() != nil {
			return findings
		}
		findings = append(findings, scanJoomlaInstall(ctx, path, store)...)
	}
	return findings
}

// scanJoomlaInstall scans one discovered install and stamps its findings
// with the owner resolved from the configuration path. The display label
// stays as before; an install outside every account root is not stamped.
func scanJoomlaInstall(ctx context.Context, path string, store *state.Store) []alert.Finding {
	matched, err := looksLikeJoomlaConfig(ctx, path)
	if err != nil {
		markCheckIncomplete(ctx, "db_content_joomla")
		return nil
	}
	if !matched {
		return nil
	}
	account := extractUser(filepath.Dir(path))
	creds, err := parseJConfig(ctx, path)
	if err != nil || creds.dbName == "" || creds.dbUser == "" {
		markCheckIncomplete(ctx, "db_content_joomla")
		return nil
	}
	creds.ctx = ctx
	creds.queryState = new(dbQueryState)
	prefix := creds.dbPrefix
	if prefix == "" {
		prefix = "jos_"
	}

	var findings []alert.Finding
	findings = append(findings, scanJoomlaExtensions(account, creds, prefix)...)
	findings = append(findings, scanJoomlaContent(account, creds, prefix)...)
	findings = append(findings, scanJoomlaSuperUsers(store, account, creds, prefix)...)
	if owner, ok := installOwner(path); ok {
		findings = stampTenantIDIfEmpty(findings, owner)
	}
	return findings
}

// A defaced configuration can still identify a Joomla installation. Its
// credentials are parsed without executing any PHP.
func looksLikeJoomlaConfig(ctx context.Context, path string) (bool, error) {
	data, err := readCMSConfig(ctx, path)
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(string(data)), "class jconfig"), nil
}

// parseJConfig reads configuration.php and pulls credentials out of
// the public-property assignments. Lines outside the class body
// (PHP comments, namespaced statements, etc.) are tolerated
// silently because the regex is line-anchored to "public $foo = ...".
func parseJConfig(ctx context.Context, path string) (jConfigCreds, error) {
	creds := jConfigCreds{path: path}
	data, err := readCMSConfig(ctx, path)
	if err != nil {
		return creds, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		m := jConfigCredsPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		switch strings.ToLower(m[1]) {
		case "host":
			creds.dbHost = m[2]
		case "user":
			creds.dbUser = m[2]
		case "password":
			creds.dbPass = m[2]
		case "db":
			creds.dbName = m[2]
		case "dbprefix":
			creds.dbPrefix = m[2]
		}
	}
	if creds.dbHost == "" {
		creds.dbHost = "localhost"
	}
	return creds, nil
}

// scanJoomlaExtensions queries the extensions table for params
// blobs that match the malware-pattern pre-filter, then applies a
// Go-side post-filter to drop rows whose only match was <script>
// LIKE noise (legitimate analytics embeds in extension params).
//
// Two-phase classifier:
//
//  1. SQL pre-filter via LIKE keeps the result set bounded -- a
//     vanilla Joomla #__extensions table has ~50 rows, but a
//     plugin-heavy install can exceed 200, and we don't want to
//     pull every params blob into the daemon.
//
//  2. Go classifyMalwareRow re-checks each pattern individually
//     against the full body, applying the same requiresExternalScript
//     filter the WP scanner uses for wp_options. Strict predicate
//     here (hasMaliciousExternalScript) because params is config
//     storage.
func scanJoomlaExtensions(account string, creds jConfigCreds, prefix string) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT name, params FROM %sextensions WHERE %s",
		prefix, paramsLikeClause("params"))
	rows, _ := runCMSQuery(creds.asWPDBCreds(), query)
	var findings []alert.Finding
	for _, row := range rows {
		name, body := splitTabRow(row)
		if name == "" {
			continue
		}
		sev, desc, ok := classifyMalwareRow(body, false)
		if !ok {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: sev,
			Check:    "joomla_extensions_injection",
			Message:  fmt.Sprintf("Joomla extension params injection on %s: %s (%s)", account, name, desc),
			Details:  fmt.Sprintf("Account: %s\nExtension: %s\nMatch: %s", account, name, desc),
		})
	}
	return findings
}

// scanJoomlaContent queries article bodies (introtext) for malware
// patterns. Same two-phase classifier as scanJoomlaExtensions but
// uses the looser post-filter (hasMaliciousExternalScriptInPost)
// because articles are author-written and may carry pre-TLS-era
// embeds the strict predicate would flag on scheme alone.
//
// fulltext_ is not scanned in v1: it's almost never populated on
// modern Joomla installs (the read-more split is a layout choice
// most templates don't bother with), and adding it doubles the
// query cost for marginal coverage. Follow-up if operators see
// missed detections.
func scanJoomlaContent(account string, creds jConfigCreds, prefix string) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT id, title, introtext FROM %scontent WHERE %s",
		prefix, paramsLikeClause("introtext"))
	rows, _ := runCMSQuery(creds.asWPDBCreds(), query)
	var findings []alert.Finding
	for _, row := range rows {
		fields := strings.SplitN(row, "\t", 3)
		if len(fields) < 3 {
			continue
		}
		id, title, body := fields[0], fields[1], fields[2]
		sev, desc, ok := classifyMalwareRow(body, true)
		if !ok {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: sev,
			Check:    "joomla_content_injection",
			Message:  fmt.Sprintf("Joomla article content injection on %s: id=%s title=%q (%s)", account, id, title, desc),
			Details:  fmt.Sprintf("Account: %s\nArticle ID: %s\nTitle: %s\nMatch: %s", account, id, title, desc),
		})
	}
	return findings
}

// classifyMalwareRow walks dbMalwarePatterns against body and
// returns the strongest pattern match that survives the
// requiresExternalScript filter. Returns ok=false when nothing
// genuine matched -- the caller skips that row entirely.
//
// inPostContext switches between the strict
// hasMaliciousExternalScript (for config-storage rows like Joomla
// extension params or Drupal config) and the looser
// hasMaliciousExternalScriptInPost (for author-written article
// content). Mirrors how the WP scanner picks its predicate per
// table. Shared by the Joomla and Drupal scanners; the function
// lives in dbscan_joomla.go for historical reasons (added with
// the Joomla scanner; renamed when Drupal also needed it).
func classifyMalwareRow(body string, inPostContext bool) (alert.Severity, string, bool) {
	if body == "" {
		return 0, "", false
	}
	lower := strings.ToLower(body)

	var bestSev alert.Severity
	var bestDesc string
	matched := false
	for _, p := range dbMalwarePatterns {
		if !strings.Contains(lower, strings.ToLower(p.pattern)) {
			continue
		}
		if p.requiresExternalScript {
			ok := hasMaliciousExternalScript(body)
			if inPostContext {
				ok = hasMaliciousExternalScriptInPost(body)
			}
			if !ok {
				continue
			}
		}
		if !matched || p.severity > bestSev {
			bestSev = p.severity
			bestDesc = p.desc
		}
		matched = true
	}
	return bestSev, bestDesc, matched
}

// scanJoomlaSuperUsers detects rogue accounts in the Super Users
// group (group_id = 8 by default). The two-table join is necessary
// because Joomla stores group membership separately from the user
// row; a single rogue admin shows up only when the join fires.
func scanJoomlaSuperUsers(store *state.Store, account string, creds jConfigCreds, prefix string) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT u.id, u.username, u.email FROM %susers u JOIN %suser_usergroup_map m ON u.id = m.user_id WHERE m.group_id = %d",
		prefix, prefix, joomlaSuperUserGroupID)
	rows, complete := runCMSQuery(creds.asWPDBCreds(), query)
	// The legitimate site admin is in this set too: the store baseline
	// keeps known Super Users quiet and reports only a newcomer.
	dbCreds := creds.asWPDBCreds()
	dbCreds.tablePrefix = prefix
	return cmsAdminFindings(store, "joomla", "joomla_admin_injection", account, dbCreds, rows, complete, func(fields []string) (string, string) {
		return fmt.Sprintf("Joomla Super User account on %s: %s", account, fields[0]),
			fmt.Sprintf("Account: %s\nRow: %s\nReview: confirm this is the legitimate site administrator.", account, strings.Join(fields, "\t"))
	})
}

// paramsLikeClause builds an OR'd LIKE clause over the supplied
// columns and the existing dbMalwarePatterns list. The patterns
// are escaped for MySQL string literal syntax (single quotes
// doubled, backslashes doubled).
//
// We use plain LIKE rather than full-text search so the query
// runs against any MySQL configuration -- some shared-hosting
// instances have ngram FTS off, and we don't want to depend on
// it for a security scan.
func paramsLikeClause(columns ...string) string {
	if len(columns) == 0 {
		return "1=0"
	}
	var clauses []string
	for _, col := range columns {
		for _, p := range dbMalwarePatterns {
			lit := mysqlEscapeForLike(p.pattern)
			clauses = append(clauses, fmt.Sprintf("%s LIKE '%%%s%%'", col, lit))
		}
	}
	return strings.Join(clauses, " OR ")
}

// mysqlEscapeForLike escapes a literal for use inside a single-quoted
// MySQL LIKE pattern. Only `'` and `\` need escaping; LIKE's `%` and
// `_` are intentionally left alone because the malware-pattern list
// uses literal substrings and never SQL wildcards.
func mysqlEscapeForLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s
}
