package checks

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// reAccountName matches the cPanel-username shape we accept from
// operator CLI input. Constrained on purpose: anything outside this
// charset would either fail later validation (QuoteIdent on schema)
// or escape /home via the path interpolation in findAccountSchemas
// when an unwary glob expanded a `*`.
var reAccountName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,31}$`)

// errInvalidAccountName flags an account string that fails the
// allowed-charset check. Surfaced through the CLI so the operator
// sees a clear error before any filesystem or SQL lookup.
var errInvalidAccountName = errors.New("invalid account name (want [a-zA-Z][a-zA-Z0-9_-]{0,31})")

// DBDropObject drops a single trigger / event / stored procedure /
// stored function from the operator-supplied account+schema, after:
//
//  1. Validating the kind ("trigger" | "event" | "procedure" | "function").
//  2. Validating that <schema> is one of the databases this account
//     hosts. The account is taken from /home/<account>/* wp-config.php
//     files; an attacker who can pass an arbitrary <schema> here gets
//     no further than DROP'ping their own database.
//  3. QuoteIdent on both <schema> and <name>, so identifier strings
//     never participate in SQL string concatenation.
//  4. SHOW CREATE the object and persist the result to the
//     db_object_backups bbolt bucket as the backup -- replaying the
//     CREATE SQL restores the object byte-for-byte.
//  5. DROP the object.
//
// preview=true short-circuits before step 4: the function reports
// what it would do (kind, schema, name, captured CREATE SQL) without
// touching the database.
//
// Per spec: detection is always-on; drop is operator-driven.
func DBDropObject(account, schema, kind, name string, preview bool) DBCleanResult {
	result := DBCleanResult{
		Account: account,
		Action:  "drop-object",
	}

	if !reAccountName.MatchString(account) {
		result.Message = fmt.Sprintf("%v: %q", errInvalidAccountName, account)
		return result
	}
	if !IsDBObjectKind(kind) {
		result.Message = fmt.Sprintf("Invalid object kind %q (want trigger|event|procedure|function)", kind)
		return result
	}
	quotedSchema, err := QuoteIdent(schema)
	if err != nil {
		result.Message = fmt.Sprintf("Invalid schema name: %v", err)
		return result
	}
	quotedName, err := QuoteIdent(name)
	if err != nil {
		result.Message = fmt.Sprintf("Invalid object name: %v", err)
		return result
	}

	knownSchemas := findAccountSchemas(account)
	if !containsString(knownSchemas, schema) {
		result.Message = fmt.Sprintf("Schema %q is not one of the databases discovered for account %q (known: %v)",
			schema, account, knownSchemas)
		return result
	}
	result.Database = schema

	// SHOW CREATE captures the backup. Different MySQL grammars per
	// kind: TRIGGER and EVENT use the schema-qualified name in
	// `<schema>.<name>` form; PROCEDURE and FUNCTION accept the same
	// shape under modern MySQL. Use the unified form for consistency.
	showCreateSQL := fmt.Sprintf("SHOW CREATE %s %s.%s",
		strings.ToUpper(kind), quotedSchema, quotedName)
	createOutput := runMySQLQueryRoot(schema, showCreateSQL)
	if len(createOutput) == 0 {
		result.Message = fmt.Sprintf("SHOW CREATE returned no rows for %s %s.%s -- object missing or permission denied",
			kind, schema, name)
		return result
	}
	createSQL := strings.Join(createOutput, "\n")

	if preview {
		result.Message = fmt.Sprintf("PREVIEW: would drop %s %s.%s", kind, schema, name)
		result.Details = []string{
			fmt.Sprintf("Captured CREATE SQL (%d bytes)", len(createSQL)),
			"No backup written and no DROP executed in preview mode.",
		}
		result.Success = true
		return result
	}

	// Persist backup BEFORE the drop so a SQL failure on DROP still
	// leaves the operator with a record of what existed.
	sdb := store.Global()
	if sdb == nil {
		result.Message = "bbolt store not available; refusing to drop without a recorded backup"
		return result
	}
	if err := sdb.PutDBObjectBackup(store.DBObjectBackup{
		Account:   account,
		Schema:    schema,
		Kind:      kind,
		Name:      name,
		CreateSQL: createSQL,
		DroppedAt: time.Now().UTC(),
		DroppedBy: "csm-cli",
	}); err != nil {
		result.Message = fmt.Sprintf("recording backup failed (refusing to drop): %v", err)
		return result
	}

	dropSQL := fmt.Sprintf("DROP %s IF EXISTS %s.%s",
		strings.ToUpper(kind), quotedSchema, quotedName)
	// runMySQLExecRoot reports the mysql client's exec error
	// directly. The previous use of runMySQLQueryRoot misread a
	// zero-exit + empty-stdout (the success signature for DROP) as
	// failure.
	if err := runMySQLExecRoot(schema, dropSQL); err != nil {
		result.Message = fmt.Sprintf("DROP %s %s.%s failed: %v", kind, schema, name, err)
		return result
	}

	result.Details = []string{
		fmt.Sprintf("Dropped %s %s.%s", kind, schema, name),
		fmt.Sprintf("Backup recorded in bbolt: %d bytes", len(createSQL)),
	}
	result.Message = fmt.Sprintf("Dropped %s %s.%s (backup retained)", kind, schema, name)
	result.Success = true
	return result
}

// findAccountSchemas returns every distinct database name discovered
// across the account's wp-config.php files. Multiple WordPress
// installations under the same account commonly reuse one database
// but can use several; the CLI relies on this list to validate
// operator input before opening any connection.
func findAccountSchemas(account string) []string {
	patterns := []string{
		fmt.Sprintf("/home/%s/public_html/wp-config.php", account),
	}
	addonConfigs, _ := osFS.Glob(fmt.Sprintf("/home/%s/*/wp-config.php", account))
	patterns = append(patterns, addonConfigs...)

	seen := map[string]struct{}{}
	var out []string
	for _, path := range patterns {
		// parseWPConfig handles missing files silently, so the bare
		// non-glob first-entry path is harmless when the account has
		// no public_html/wp-config.php.
		creds := parseWPConfig(path)
		if creds.dbName == "" {
			continue
		}
		if _, ok := seen[creds.dbName]; ok {
			continue
		}
		seen[creds.dbName] = struct{}{}
		out = append(out, creds.dbName)
	}
	return out
}

// containsString reports whether haystack contains needle. Local
// because the package's other helper of the same name lives in a
// _test.go file (waf_test.go) and is not visible to production
// builds.
func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// RestoreDBObjectBackup re-executes the captured CREATE SQL for a
// previously-dropped MySQL trigger / event / procedure / function.
// Looks up the row in the db_object_backups bbolt bucket by exact
// key; the caller (typically the web UI's cleanup-history page)
// supplies the key it got from the listing endpoint.
//
// Per spec the operation is operator-driven: there is no auto-
// restore. The webui handler enforces the same.
func RestoreDBObjectBackup(backupKey string) DBCleanResult {
	result := DBCleanResult{Action: "restore-object"}

	sdb := store.Global()
	if sdb == nil {
		result.Message = "bbolt store not available"
		return result
	}
	rec, ok, err := sdb.GetDBObjectBackupByKey(backupKey)
	if err != nil {
		result.Message = fmt.Sprintf("looking up backup: %v", err)
		return result
	}
	if !ok {
		result.Message = "backup not found (may have been pruned)"
		return result
	}

	result.Account = rec.Account
	result.Database = rec.Schema
	if rec.CreateSQL == "" {
		result.Message = "backup record has no CREATE SQL"
		return result
	}
	if err := runMySQLExecRoot(rec.Schema, rec.CreateSQL); err != nil {
		result.Message = fmt.Sprintf("re-executing CREATE failed: %v", err)
		return result
	}
	result.Details = []string{
		fmt.Sprintf("Restored %s %s.%s", rec.Kind, rec.Schema, rec.Name),
		fmt.Sprintf("Original drop: %s by %s", rec.DroppedAt.Format(time.RFC3339), rec.DroppedBy),
	}
	result.Message = fmt.Sprintf("Restored %s %s.%s from backup", rec.Kind, rec.Schema, rec.Name)
	result.Success = true
	return result
}
