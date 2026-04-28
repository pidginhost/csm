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
	dbName   string
	dbUser   string
	dbPass   string
	dbHost   string
	dbPrefix string
	path     string
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
	}
}

// CheckJoomlaContent scans every Joomla installation under
// /home/*/public_html for malware-pattern matches in the three
// canonical attacker-touched tables. Mirrors the structure of
// CheckDatabaseContent without sharing code -- the credentials and
// table layout differ enough that a generic dispatcher is more
// abstraction than this point in the codebase needs.
func CheckJoomlaContent(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	configs, _ := osFS.Glob("/home/*/public_html/configuration.php")
	if len(configs) == 0 {
		return nil
	}

	for _, path := range configs {
		if !looksLikeJoomlaConfig(path) {
			continue
		}
		account := extractUser(filepath.Dir(path))
		creds := parseJConfig(path)
		if creds.dbName == "" || creds.dbUser == "" {
			continue
		}
		prefix := creds.dbPrefix
		if prefix == "" {
			prefix = "jos_"
		}

		findings = append(findings, scanJoomlaExtensions(account, creds, prefix)...)
		findings = append(findings, scanJoomlaContent(account, creds, prefix)...)
		findings = append(findings, scanJoomlaSuperUsers(account, creds, prefix)...)
	}
	return findings
}

// looksLikeJoomlaConfig reads the file looking for the `class JConfig`
// marker. The file must be small enough that a full read is cheap
// (vanilla Joomla configuration.php is ~3 KB; a hostile multi-MB
// file would be unusual but we cap implicitly via Open + ReadFile).
func looksLikeJoomlaConfig(path string) bool {
	// #nosec G304 -- path resolved via osFS.Glob over /home/*/public_html; not attacker-controlled.
	data, err := osFS.ReadFile(path)
	if err != nil {
		return false
	}
	// A defaced configuration.php that still has the class
	// declaration but injected malicious public properties is
	// exactly what we WANT to scan. Marker check is intentionally
	// loose: any occurrence of `class JConfig` (case-insensitive on
	// the keyword `class`).
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "class jconfig")
}

// parseJConfig reads configuration.php and pulls credentials out of
// the public-property assignments. Lines outside the class body
// (PHP comments, namespaced statements, etc.) are tolerated
// silently because the regex is line-anchored to "public $foo = ...".
func parseJConfig(path string) jConfigCreds {
	creds := jConfigCreds{path: path}
	// #nosec G304 -- same Glob-resolved path as above.
	data, err := osFS.ReadFile(path)
	if err != nil {
		return creds
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
	return creds
}

// scanJoomlaExtensions queries the extensions table for params
// blobs containing any malware pattern. The params column carries
// JSON-serialized configuration; attackers commonly inject script
// tags or external loader URLs into the system extensions.
func scanJoomlaExtensions(account string, creds jConfigCreds, prefix string) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT name, params FROM %sextensions WHERE %s",
		prefix, paramsLikeClause("params"))
	return runJoomlaScan(creds.asWPDBCreds(), query,
		"joomla_extensions_injection",
		fmt.Sprintf("Joomla extension params injection on %s", account))
}

// scanJoomlaContent queries article bodies (introtext + fulltext)
// for malware patterns. Attackers use article injection both for
// SEO spam and as a delivery vector for second-stage browser
// exploits.
func scanJoomlaContent(account string, creds jConfigCreds, prefix string) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT id, title FROM %scontent WHERE %s",
		prefix, paramsLikeClause("introtext", "fulltext_"))
	// MySQL reserved words: `fulltext` is reserved, the column is
	// `fulltext_`. Both Joomla 3 and 4 use the underscored form.
	return runJoomlaScan(creds.asWPDBCreds(), query,
		"joomla_content_injection",
		fmt.Sprintf("Joomla article content injection on %s", account))
}

// scanJoomlaSuperUsers detects rogue accounts in the Super Users
// group (group_id = 8 by default). The two-table join is necessary
// because Joomla stores group membership separately from the user
// row; a single rogue admin shows up only when the join fires.
func scanJoomlaSuperUsers(account string, creds jConfigCreds, prefix string) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT u.id, u.username, u.email FROM %susers u JOIN %suser_usergroup_map m ON u.id = m.user_id WHERE m.group_id = %d",
		prefix, prefix, joomlaSuperUserGroupID)
	rows := runMySQLQuery(creds.asWPDBCreds(), query)
	if len(rows) == 0 {
		return nil
	}
	// Operator-review territory: the legitimate site admin shows up
	// here too. We emit a Warning per row so operators can confirm.
	// A separate Critical detector for accounts created in the last
	// hour is a follow-up; v1 emits visibility only.
	var findings []alert.Finding
	for _, row := range rows {
		fields := strings.Split(row, "\t")
		if len(fields) < 1 {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: alert.Warning,
			Check:    "joomla_admin_injection",
			Message:  fmt.Sprintf("Joomla Super User account on %s: %s", account, fields[0]),
			Details:  fmt.Sprintf("Account: %s\nRow: %s\nReview: confirm this is the legitimate site administrator.", account, row),
		})
	}
	return findings
}

// runJoomlaScan executes the supplied query (which already filters
// for malware patterns) and emits one finding per row. The query
// is expected to return identifying columns -- name, id, etc. --
// not the full payload, since we already know the row matched.
func runJoomlaScan(creds wpDBCreds, query, checkName, messagePrefix string) []alert.Finding {
	rows := runMySQLQuery(creds, query)
	if len(rows) == 0 {
		return nil
	}
	var findings []alert.Finding
	for _, row := range rows {
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    checkName,
			Message:  fmt.Sprintf("%s: %s", messagePrefix, row),
			Details:  fmt.Sprintf("Row: %s\nMatch: malware pattern in tracked column", row),
		})
	}
	return findings
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
