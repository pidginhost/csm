package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// DB persistence-mechanism scanner.
//
// Vanilla CMS installs (WordPress, Joomla, Drupal, Magento, OpenCart)
// ship zero triggers / events / stored procedures / stored functions.
// Any presence is operator-review territory at minimum, and a body
// matching known-malware patterns is critical -- attacker persistence
// often re-injects on the next INSERT after a file-level cleanup, so
// detection here closes a real gap.
//
// The scanner reuses the existing parseWPConfig + runMySQLQuery
// infrastructure from dbscan.go. When the multi-CMS adapter layer
// lands later, this file's helpers become reusable across CMSes by
// swapping the credential discovery, not the queries.
//
// Per spec: detection only, no auto-drop. Operators drop manually
// via `csm db-clean drop-object`.

// dbPersistenceMalwarePatterns supplements dbMalwarePatterns from
// dbscan.go with MySQL-specific persistence-attack signals. Lowercase
// for case-insensitive matching against SQL bodies.
var dbPersistenceMalwarePatterns = []string{
	"sys_exec",
	"lib_mysqludf_sys",
	"into outfile",
	"into dumpfile",
	"load_file(",
	"load data infile",
}

// magicTokenRegex extracts high-entropy activation tokens from trigger
// bodies that gate privileged actions on `display_name LIKE
// '%<token>%'`. Common display-name filters such as "%administrator%"
// must not escalate a merely unexpected trigger into Critical.
var magicTokenRegex = regexp.MustCompile(`(?i)display_name\s+like\s+['"]%([A-Za-z0-9_-]{10,32})%['"]`)

// validTablePrefix matches the character class WordPress accepts for
// $table_prefix (alphanumerics and underscore). Untrusted prefixes
// from a malformed wp-config.php fail this check, which keeps
// scanMagicTokenUsers from concatenating attacker-controlled data into
// its SQL literal.
var validTablePrefix = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// dbPersistenceMalwareRegexes catches multi-token shapes that no
// substring set can match cleanly: role-escalation writes and
// password-hash exfiltration reads. Pre-compiled at package init time
// -- a regex parse error here is a build-time bug, not a runtime one.
//
// Patterns intentionally case-insensitive ((?i) prefix) and tolerant of
// whitespace / line breaks across MySQL trigger bodies. The role-write
// pattern requires the literal string "administrator" inside the
// serialized capabilities payload -- promotion to subscriber/customer
// is the legitimate WP-signup shape and must not match.
var dbPersistenceMalwareRegexes = []*regexp.Regexp{
	// Role escalation: UPDATE on *_usermeta writing administrator caps.
	// The (?s) flag lets `.` match newlines so multi-line trigger
	// bodies with the UPDATE split across lines still hit.
	regexp.MustCompile(`(?is)update\s+` + "`?" + `\w*usermeta` + "`?" + `\s+set\s+meta_value\s*=.*?(?:s:13:["\x60]administrator["\x60]|["\x60]administrator["\x60])`),
	// Password-hash exfil read: SELECT user_pass FROM <users-like>
	// table. Real WP code goes through wp_check_password() in PHP, never
	// raw SELECT user_pass from SQL.
	regexp.MustCompile(`(?i)select\s+user_pass\s+from\s+` + "`?" + `\w*users`),
}

// dbObjectKind names the four MySQL object types this scanner
// inspects. Used in finding categories and CLI subcommands.
type dbObjectKind string

const (
	dbObjectTrigger   dbObjectKind = "trigger"
	dbObjectEvent     dbObjectKind = "event"
	dbObjectProcedure dbObjectKind = "procedure"
	dbObjectFunction  dbObjectKind = "function"
)

// dbObjectAllKinds lists all valid kinds for the CLI's type validator.
var dbObjectAllKinds = []dbObjectKind{
	dbObjectTrigger, dbObjectEvent, dbObjectProcedure, dbObjectFunction,
}

// dbObjectFinding describes one detector hit before it is converted
// to an alert.Finding -- carrying the structured fields the CLI
// drop-object subcommand needs to look up the same row.
type dbObjectFinding struct {
	Account string
	Schema  string
	Kind    dbObjectKind
	Name    string
	Body    string
	IsMalw  bool // true: malware pattern hit; false: unexpected presence
}

// CheckDatabaseObjects scans every WordPress installation's database
// for triggers, events, procedures, and functions. Critical findings
// fire when the body matches a known-malware pattern; Warning
// findings fire when an object exists at all (vanilla CMSes ship
// none). The Detection.DBObjectScanning kill-switch silences both
// emit paths without disabling the manual drop-object CLI.
func CheckDatabaseObjects(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if !dbObjectScanningEnabled(cfg) {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var findings []alert.Finding
	wpConfigs, _ := osFS.Glob("/home/*/public_html/wp-config.php")
	if len(wpConfigs) == 0 {
		return nil
	}

	allowlist := dbObjectAllowlistMap(cfg)

	// Rank by mtime desc so recently touched WP installs are processed
	// first when the check timeout cuts iteration short.
	for _, wpConfig := range rankPathsByMtimeDesc(ctx, wpConfigs, 0) {
		if ctx.Err() != nil {
			return findings
		}
		account := extractUser(filepath.Dir(wpConfig))
		creds := parseWPConfig(wpConfig)
		if creds.dbName == "" || creds.dbUser == "" {
			continue
		}
		hits := scanDBObjects(account, creds)
		for _, h := range hits {
			if !h.IsMalw && allowlist[allowlistKey(h)] {
				continue
			}
			findings = append(findings, h.toFinding())
		}
		// Retro-scan: when a trigger gates a privileged action on a
		// secret token in display_name, find users whose display_name
		// still carries the token. Zero matches is itself useful for
		// the incident report ("no evidence the backdoor fired").
		for _, h := range hits {
			if h.Kind != dbObjectTrigger {
				continue
			}
			tokens := extractMagicTokens(h.Body)
			if len(tokens) == 0 {
				continue
			}
			findings = append(findings, scanMagicTokenUsers(account, creds.dbName, creds.tablePrefix, tokens)...)
		}
	}
	return findings
}

// scanDBObjects runs the three INFORMATION_SCHEMA queries and
// classifies every row. Pure function over the cmdExec injector --
// tests provide canned MySQL CLI output and assert on the structured
// findings without touching a real database.
//
// Connections use root credentials via /root/.my.cnf. WP-config
// passwords are unreliable on cPanel hosts (password rotations
// don't update the file), so a WP-creds path here would silently
// miss persistence objects on the very platform we care most about.
// The existing db-clean code (db_clean.go: findCredsForAccount)
// hits the same constraint and reaches the same conclusion.
func scanDBObjects(account string, creds wpDBCreds) []dbObjectFinding {
	if creds.dbName == "" {
		return nil
	}
	schema := creds.dbName
	schemaLit := mysqlSchemaLiteral(schema)
	var hits []dbObjectFinding

	// TRIGGERS
	for _, row := range runMySQLQueryRoot(schema, fmt.Sprintf(
		`SELECT TRIGGER_NAME, ACTION_STATEMENT FROM INFORMATION_SCHEMA.TRIGGERS WHERE TRIGGER_SCHEMA = %s`,
		schemaLit)) {
		name, body := splitTabRow(row)
		if name == "" {
			continue
		}
		hits = append(hits, classifyDBObject(account, schema, dbObjectTrigger, name, body))
	}

	// EVENTS
	for _, row := range runMySQLQueryRoot(schema, fmt.Sprintf(
		`SELECT EVENT_NAME, EVENT_DEFINITION FROM INFORMATION_SCHEMA.EVENTS WHERE EVENT_SCHEMA = %s`,
		schemaLit)) {
		name, body := splitTabRow(row)
		if name == "" {
			continue
		}
		hits = append(hits, classifyDBObject(account, schema, dbObjectEvent, name, body))
	}

	// ROUTINES (procedures + functions)
	for _, row := range runMySQLQueryRoot(schema, fmt.Sprintf(
		`SELECT ROUTINE_NAME, ROUTINE_TYPE, ROUTINE_DEFINITION FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_SCHEMA = %s`,
		schemaLit)) {
		name, rtype, body := splitTabRow3(row)
		if name == "" {
			continue
		}
		kind := dbObjectProcedure
		if strings.EqualFold(rtype, "FUNCTION") {
			kind = dbObjectFunction
		}
		hits = append(hits, classifyDBObject(account, schema, kind, name, body))
	}

	return hits
}

// classifyDBObject decides whether a row matches the malware
// patterns (Critical) or merely exists (Warning).
func classifyDBObject(account, schema string, kind dbObjectKind, name, body string) dbObjectFinding {
	return dbObjectFinding{
		Account: account,
		Schema:  schema,
		Kind:    kind,
		Name:    name,
		Body:    body,
		IsMalw:  bodyHasMalwarePattern(body),
	}
}

// bodyHasMalwarePattern returns true when the SQL body matches any of
// the three classifier tiers:
//
//  1. dbMalwarePatterns / dbPersistenceMalwarePatterns: substring tokens
//     for OS-exec UDFs and file-IO sinks (sys_exec, INTO OUTFILE, etc.).
//  2. extractMagicTokens: high-entropy display_name activation gates.
//  3. dbPersistenceMalwareRegexes: multi-token shapes for role-escalation
//     writes and password-hash exfiltration reads.
//
// Substring matching stays case-insensitive via ToLower; the regex tier
// keeps its own `(?i)` flags so its semantics travel with the pattern.
func bodyHasMalwarePattern(body string) bool {
	lower := strings.ToLower(body)
	for _, p := range dbMalwarePatterns {
		if strings.Contains(lower, strings.ToLower(p.pattern)) {
			return true
		}
	}
	for _, p := range dbPersistenceMalwarePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	if len(extractMagicTokens(body)) > 0 {
		return true
	}
	for _, re := range dbPersistenceMalwareRegexes {
		if re.MatchString(body) {
			return true
		}
	}
	return false
}

// toFinding renders the structured hit into the alert.Finding shape
// the rest of the pipeline expects. Finding category encodes both
// kind and severity tier so operators can suppress per attack type.
func (h dbObjectFinding) toFinding() alert.Finding {
	check := fmt.Sprintf("db_unexpected_%s", h.Kind)
	severity := alert.Warning
	intro := "Unexpected"
	if h.IsMalw {
		check = fmt.Sprintf("db_malicious_%s", h.Kind)
		severity = alert.Critical
		intro = "Malicious"
	}
	excerpt := h.Body
	if len(excerpt) > 240 {
		excerpt = excerpt[:240] + "..."
	}
	return alert.Finding{
		Severity:  severity,
		Check:     check,
		Message:   fmt.Sprintf("%s %s %s in %s.%s", intro, h.Kind, h.Name, h.Account, h.Schema),
		Details:   fmt.Sprintf("Account: %s\nSchema: %s\nKind: %s\nName: %s\nBody: %s", h.Account, h.Schema, h.Kind, h.Name, excerpt),
		Timestamp: time.Now(),
	}
}

// allowlistKey shapes the suppression key per spec:
// `<account>:<schema>:<type>:<name>`. Used for the Warning tier
// only -- Critical malware-pattern hits always fire.
func allowlistKey(h dbObjectFinding) string {
	return fmt.Sprintf("%s:%s:%s:%s", h.Account, h.Schema, h.Kind, h.Name)
}

func dbObjectAllowlistMap(cfg *config.Config) map[string]bool {
	out := map[string]bool{}
	if cfg == nil {
		return out
	}
	for _, e := range cfg.Detection.DBObjectAllowlist {
		out[strings.TrimSpace(e)] = true
	}
	return out
}

// splitTabRow returns the first two tab-separated fields from a
// MySQL `-B -N` row. Empty strings if the row has fewer than two
// fields.
func splitTabRow(row string) (string, string) {
	parts := strings.SplitN(row, "\t", 2)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// splitTabRow3 returns the first three tab-separated fields. Used
// for ROUTINES which carries (name, type, body).
func splitTabRow3(row string) (string, string, string) {
	parts := strings.SplitN(row, "\t", 3)
	if len(parts) < 3 {
		return "", "", ""
	}
	return parts[0], parts[1], parts[2]
}

// mysqlSchemaLiteral wraps the schema name as a single-quoted
// string literal with backslash escaping. The DB name comes from
// wp-config.php (operator-controlled) so the risk is low, but the
// string-literal route is consistent with how the existing dbscan
// queries handle string args.
func mysqlSchemaLiteral(name string) string {
	escaped := strings.ReplaceAll(name, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `\'`)
	return "'" + escaped + "'"
}

// dbObjectScanningEnabled resolves the tri-state cfg flag: nil and
// missing-config both mean default-on; an explicit *false means off.
func dbObjectScanningEnabled(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	if cfg.Detection.DBObjectScanning == nil {
		return true
	}
	return *cfg.Detection.DBObjectScanning
}

// IsDBObjectKind reports whether s is one of the four valid kinds.
// Used by the CLI subcommand to validate user input before opening
// a connection.
func IsDBObjectKind(s string) bool {
	for _, k := range dbObjectAllKinds {
		if string(k) == s {
			return true
		}
	}
	return false
}

// extractMagicTokens returns the secret activation tokens referenced in
// a trigger body's `display_name LIKE '%<token>%'` clauses. The body
// classifier uses the same helper, and the user retro scan reuses the
// returned tokens to search the *_users table for matches. Tokens are
// deduplicated to keep query count bounded when a trigger references
// the same token across multiple branches.
//
// Returns nil for benign bodies so callers can skip MySQL entirely.
func extractMagicTokens(body string) []string {
	matches := magicTokenRegex.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	var out []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		tok := m[1]
		if !validMagicToken(tok) {
			continue
		}
		if _, ok := seen[tok]; ok {
			continue
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
	}
	return out
}

func validMagicToken(tok string) bool {
	if len(tok) < 10 || len(tok) > 32 {
		return false
	}
	hasUpper, hasLower, hasDigit := false, false, false
	for _, r := range tok {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return hasUpper && hasLower && hasDigit
}

// scanMagicTokenUsers searches the WordPress users table for accounts
// whose display_name carries a backdoor activation token. A match is
// forensic evidence that the trigger fired against that user -- they
// may still be administrator, or the attacker may have demoted them
// after promotion. Either way the user requires manual review and is
// surfaced as Critical.
//
// The function is conservative about query construction. Tokens are
// guaranteed to be high-entropy [A-Za-z0-9_-]{10,32} strings by
// extractMagicTokens, and the table prefix is validated against
// [A-Za-z0-9_]+ before concatenation. Anything outside those character
// classes causes the scan to skip the query entirely rather than emit a
// half-built SQL statement against an untrusted prefix.
func scanMagicTokenUsers(account, schema, tablePrefix string, tokens []string) []alert.Finding {
	if len(tokens) == 0 || tablePrefix == "" || !validTablePrefix.MatchString(tablePrefix) {
		return nil
	}
	var findings []alert.Finding
	for _, tok := range tokens {
		if !validMagicToken(tok) {
			continue
		}
		query := fmt.Sprintf(
			"SELECT ID, user_login, user_email, display_name FROM `%susers` WHERE display_name LIKE '%%%s%%'",
			tablePrefix, tok,
		)
		rows := runMySQLQueryRoot(schema, query)
		for _, row := range rows {
			parts := strings.SplitN(row, "\t", 4)
			if len(parts) < 4 {
				continue
			}
			userID, userLogin, userEmail, displayName := parts[0], parts[1], parts[2], parts[3]
			findings = append(findings, alert.Finding{
				Severity:  alert.Critical,
				Check:     "db_magic_token_user",
				Message:   fmt.Sprintf("User %s (ID %s) carries backdoor activation token in %s.%susers", userLogin, userID, account, tablePrefix),
				Details:   fmt.Sprintf("Account: %s\nSchema: %s\nToken: %s\nUser ID: %s\nUser login: %s\nUser email: %s\nDisplay name: %s", account, schema, tok, userID, userLogin, userEmail, displayName),
				Timestamp: time.Now(),
			})
		}
	}
	return findings
}
