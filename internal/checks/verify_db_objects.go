package checks

import (
	"context"
	"fmt"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// Per-finding Re-check for the database persistence-mechanism findings
// (triggers, events, procedures, functions) and the backdoor magic-token user
// finding. The object re-checks re-read the object's CURRENT body from
// INFORMATION_SCHEMA (not the truncated copy stored in the finding details) and
// re-run the same malware classifier the detector used, so a partially-cleaned
// object is never mistaken for a fixed one. All queries run as root and any
// failure returns Checked:false.

// runDBVerifyQueryRootGlobal runs a root query with no pinned default schema,
// for INFORMATION_SCHEMA lookups whose WHERE clause already scopes the schema.
// If the account database was dropped entirely, the object is gone with it and
// the query simply returns zero rows -- the correct "resolved" signal.
func runDBVerifyQueryRootGlobal(query string, args ...any) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbVerifyTimeout)
	defer cancel()
	return mysqlclient.RootQuery(ctx, query, args...)
}

// verifyDBObject re-checks an unexpected/malicious trigger, event, procedure, or
// function. For the unexpected tier any surviving object keeps the finding
// active. For the malicious tier the finding clears when the object is gone or
// its current body no longer matches a malware pattern.
func verifyDBObject(message, details string, malicious bool) VerifyResult {
	schema := detailField(details, "Schema")
	kind := detailField(details, "Kind")
	name := detailField(details, "Name")
	if schema == "" || name == "" || !IsDBObjectKind(kind) {
		return VerifyResult{Checked: false, Detail: "could not parse the database object from the finding"}
	}
	body, present, err := fetchDBObjectBody(schema, dbObjectKind(kind), name)
	if err != nil {
		return dbVerifyQueryError()
	}
	if !present {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("%s %q no longer exists", kind, name)}
	}
	if !malicious {
		return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("%s %q is still present", kind, name)}
	}
	if bodyHasMalwarePattern(body) {
		return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("%s %q still matches a malware pattern", kind, name)}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("%s %q no longer matches a malware pattern", kind, name)}
}

// fetchDBObjectBody returns the current definition body of one database object
// and whether it still exists. The object name and schema are passed as bound
// parameters so a malformed finding cannot inject into the lookup.
func fetchDBObjectBody(schema string, kind dbObjectKind, name string) (body string, present bool, err error) {
	var query string
	var args []any
	switch kind {
	case dbObjectTrigger:
		query = "SELECT ACTION_STATEMENT FROM INFORMATION_SCHEMA.TRIGGERS WHERE TRIGGER_SCHEMA = ? AND TRIGGER_NAME = ?"
		args = []any{schema, name}
	case dbObjectEvent:
		query = "SELECT EVENT_DEFINITION FROM INFORMATION_SCHEMA.EVENTS WHERE EVENT_SCHEMA = ? AND EVENT_NAME = ?"
		args = []any{schema, name}
	case dbObjectProcedure, dbObjectFunction:
		routineType := "PROCEDURE"
		if kind == dbObjectFunction {
			routineType = "FUNCTION"
		}
		query = "SELECT ROUTINE_DEFINITION FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_SCHEMA = ? AND ROUTINE_NAME = ? AND ROUTINE_TYPE = ?"
		args = []any{schema, name, routineType}
	default:
		return "", false, fmt.Errorf("unknown object kind")
	}
	rows, err := runDBVerifyQueryRootGlobal(query, args...)
	if err != nil {
		return "", false, err
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	return rows[0], true, nil
}

// findWPBasePrefix returns the single base table prefix for the WordPress
// install whose database matches dbName. Unlike findWPVerifyPrefixes this does
// not enumerate multisite secondary blogs -- the wp_users table is network-wide,
// so the base prefix is the only one the magic-token lookup needs.
func findWPBasePrefix(account, dbName string) (string, bool) {
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
		return resolveTablePrefix(creds)
	}
	return "", false
}

// verifyDBMagicTokenUser re-queries the WordPress users table for any account
// whose display_name still carries the backdoor activation token. The token is
// validated as the high-entropy [A-Za-z0-9_-]{10,32} shape the detector emits
// before it is used in the LIKE.
func verifyDBMagicTokenUser(message, details string) VerifyResult {
	token := detailField(details, "Token")
	if token == "" || !validMagicToken(token) {
		return VerifyResult{Checked: false, Detail: "could not parse a valid activation token from the finding"}
	}
	schema := detailField(details, "Schema")
	prefix, ok := findWPBasePrefix(dbFindingAccount(message, details), schema)
	if !ok {
		return dbVerifyNotLocatable("WordPress site")
	}
	rows, err := runDBVerifyQueryRoot(schema,
		fmt.Sprintf("SELECT ID FROM `%susers` WHERE display_name LIKE ?", prefix), "%"+token+"%")
	if err != nil {
		return dbVerifyQueryError()
	}
	if len(rows) == 0 {
		return VerifyResult{Checked: true, Resolved: true, Detail: "no user still carries the backdoor activation token"}
	}
	return VerifyResult{Checked: true, Resolved: false, Detail: "a user still carries the backdoor activation token"}
}
