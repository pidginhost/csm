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

// dbPersistenceMalwareRegexes catches multi-token shapes that no
// substring set can match cleanly: role-escalation writes, magic-token
// gating on user-controllable fields, password-hash exfiltration reads.
// Pre-compiled at package init time -- a regex parse error here is a
// build-time bug, not a runtime one.
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
	// Magic-token activation: gating any branch on `display_name LIKE
	// '%<6-32 alnum>%'`. Public profile fields are never legitimate
	// privilege-decision inputs.
	regexp.MustCompile(`(?i)display_name\s+like\s+['"]%[A-Za-z0-9_-]{6,32}%['"]`),
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

	var findings []alert.Finding
	wpConfigs, _ := osFS.Glob("/home/*/public_html/wp-config.php")
	if len(wpConfigs) == 0 {
		return nil
	}

	allowlist := dbObjectAllowlistMap(cfg)

	for _, wpConfig := range wpConfigs {
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
//  2. dbPersistenceMalwareRegexes: multi-token shapes for role-escalation
//     writes, magic-token gating on user-controllable fields, and
//     password-hash exfiltration reads.
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
