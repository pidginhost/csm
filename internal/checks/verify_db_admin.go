package checks

import (
	"fmt"
	"strings"
)

// Per-finding Re-check for the administrator-account database findings: the
// WordPress rogue-admin and disposable-email-admin findings, and the four
// per-CMS administrator findings (Drupal, Joomla, Magento, OpenCart). Each
// resolves only when the specific flagged account is no longer present (or, for
// the WordPress rogue admin, no longer holds administrator capability). A
// surviving account -- which for the per-CMS Warning findings includes the
// legitimate site administrator -- keeps the finding active for operator review.
// Any query failure or undiscoverable install returns Checked:false.

// findWPAdminVerifyPrefixes re-derives the base table prefixes for WordPress
// installs whose database matches dbName. The users/usermeta tables are
// network-wide in multisite, so this returns only each install's base prefix,
// never secondary blog prefixes.
func findWPAdminVerifyPrefixes(account, dbName, details string) ([]string, bool) {
	if !validAccountName.MatchString(account) || dbName == "" {
		return nil, false
	}
	targetPrefix := detailField(details, "Table prefix")
	if targetPrefix != "" && !validTablePrefix.MatchString(targetPrefix) {
		return nil, false
	}
	var prefixes []string
	seen := map[string]bool{}
	patterns := []string{fmt.Sprintf("/home/%s/public_html/wp-config.php", account)}
	addon, _ := osFS.Glob(fmt.Sprintf("/home/%s/*/wp-config.php", account))
	patterns = append(patterns, addon...)
	for _, path := range patterns {
		creds := parseWPConfig(path)
		if creds.dbName != dbName {
			continue
		}
		prefix, ok := resolveTablePrefix(creds)
		if !ok {
			return nil, false
		}
		if targetPrefix != "" {
			if targetPrefix == prefix {
				return []string{prefix}, true
			}
			continue
		}
		addPrefix(&prefixes, seen, prefix)
	}
	if len(prefixes) == 0 {
		return nil, false
	}
	return prefixes, true
}

// wpAdminQueryTables backtick-quotes the users and usermeta table names for the
// given (already validTablePrefix-validated) prefix.
func wpAdminQueryTables(prefix string) (users, usermeta string, ok bool) {
	u, err := QuoteIdent(prefix + "users")
	if err != nil {
		return "", "", false
	}
	m, err := QuoteIdent(prefix + "usermeta")
	if err != nil {
		return "", "", false
	}
	return u, m, true
}

// verifyDBRogueAdmin resolves when the flagged WordPress user no longer holds
// administrator capability (deleted or demoted). The detector's "created in the
// last 7 days" heuristic is intentionally NOT re-applied -- the account is older
// now; what matters for the re-check is whether that specific account is still
// an administrator.
func verifyDBRogueAdmin(message, details string) VerifyResult {
	dbName := detailField(details, "Database")
	userID := detailField(details, "User ID")
	if userID == "" || !isAllDigits(userID) {
		return VerifyResult{Checked: false, Detail: "could not parse the user ID from the finding"}
	}
	prefixes, ok := findWPAdminVerifyPrefixes(dbFindingAccount(message, details), dbName, details)
	if !ok {
		return dbVerifyNotLocatable("WordPress site")
	}
	for _, prefix := range prefixes {
		users, usermeta, ok := wpAdminQueryTables(prefix)
		if !ok {
			return VerifyResult{Checked: false, Detail: "could not validate the WordPress tables from the finding"}
		}
		rows, err := runDBVerifyQueryRoot(dbName, fmt.Sprintf(
			"SELECT u.ID FROM %s u JOIN %s m ON u.ID = m.user_id WHERE m.meta_key = ? AND m.meta_value LIKE '%%administrator%%' AND u.ID = ?",
			users, usermeta), prefix+"capabilities", userID)
		if err != nil {
			return dbVerifyQueryError()
		}
		if len(rows) > 0 {
			return VerifyResult{Checked: true, Resolved: false, Detail: "the flagged account is still a WordPress administrator"}
		}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: "the flagged account is no longer a WordPress administrator"}
}

// verifyDBSuspiciousAdminEmail resolves when no administrator still uses the
// flagged disposable email address.
func verifyDBSuspiciousAdminEmail(message, details string) VerifyResult {
	dbName := detailField(details, "Database")
	email := strings.ToLower(strings.TrimSpace(detailField(details, "Email")))
	if email == "" {
		return VerifyResult{Checked: false, Detail: "could not parse the admin email from the finding"}
	}
	prefixes, ok := findWPAdminVerifyPrefixes(dbFindingAccount(message, details), dbName, details)
	if !ok {
		return dbVerifyNotLocatable("WordPress site")
	}
	for _, prefix := range prefixes {
		users, usermeta, ok := wpAdminQueryTables(prefix)
		if !ok {
			return VerifyResult{Checked: false, Detail: "could not validate the WordPress tables from the finding"}
		}
		rows, err := runDBVerifyQueryRoot(dbName, fmt.Sprintf(
			"SELECT u.ID FROM %s u JOIN %s m ON u.ID = m.user_id WHERE m.meta_key = ? AND m.meta_value LIKE '%%administrator%%' AND LOWER(u.user_email) = ?",
			users, usermeta), prefix+"capabilities", email)
		if err != nil {
			return dbVerifyQueryError()
		}
		if len(rows) > 0 {
			return VerifyResult{Checked: true, Resolved: false, Detail: "an administrator still uses the flagged email address"}
		}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: "no administrator still uses the flagged email address"}
}

// dbAdminRowID extracts the numeric account id from a per-CMS admin finding's
// "Row:" detail line, whose first tab- (or space-) separated field is the id.
func dbAdminRowID(details string) (string, bool) {
	row := detailField(details, "Row")
	if row == "" {
		return "", false
	}
	first := row
	if i := strings.IndexAny(row, "\t "); i >= 0 {
		first = row[:i]
	}
	first = strings.TrimSpace(first)
	if first == "" || !isAllDigits(first) {
		return "", false
	}
	return first, true
}

// dbAdminPresenceResult maps a presence query result to a VerifyResult: a query
// error is never resolved; zero rows means the flagged account is gone.
func dbAdminPresenceResult(err error, rows []string) VerifyResult {
	if err != nil {
		return dbVerifyQueryError()
	}
	if len(rows) == 0 {
		return VerifyResult{Checked: true, Resolved: true, Detail: "the flagged administrator account is no longer present"}
	}
	return VerifyResult{Checked: true, Resolved: false, Detail: "the flagged administrator account is still present"}
}

func verifyDrupalAdminInjection(message, details string) VerifyResult {
	uid, ok := dbAdminRowID(details)
	if !ok {
		return VerifyResult{Checked: false, Detail: "could not parse the account id from the finding"}
	}
	schema, ok := discoverDrupalSchema(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Drupal site")
	}
	rows, err := runDBVerifyQueryRoot(schema,
		"SELECT u.uid FROM users_field_data u JOIN user__roles r ON u.uid = r.entity_id WHERE r.roles_target_id = ? AND u.default_langcode = 1 AND u.uid = ?",
		drupalAdminRoleID, uid)
	return dbAdminPresenceResult(err, rows)
}

func verifyJoomlaAdminInjection(message, details string) VerifyResult {
	id, ok := dbAdminRowID(details)
	if !ok {
		return VerifyResult{Checked: false, Detail: "could not parse the account id from the finding"}
	}
	schema, prefix, ok := discoverJoomlaSchema(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Joomla site")
	}
	users, err := QuoteIdent(prefix + "users")
	if err != nil {
		return VerifyResult{Checked: false, Detail: "could not validate the Joomla tables from the finding"}
	}
	mapTable, err := QuoteIdent(prefix + "user_usergroup_map")
	if err != nil {
		return VerifyResult{Checked: false, Detail: "could not validate the Joomla tables from the finding"}
	}
	rows, err := runDBVerifyQueryRoot(schema, fmt.Sprintf(
		"SELECT u.id FROM %s u JOIN %s m ON u.id = m.user_id WHERE m.group_id = ? AND u.id = ?",
		users, mapTable), joomlaSuperUserGroupID, id)
	return dbAdminPresenceResult(err, rows)
}

func verifyMagentoAdminInjection(message, details string) VerifyResult {
	id, ok := dbAdminRowID(details)
	if !ok {
		return VerifyResult{Checked: false, Detail: "could not parse the account id from the finding"}
	}
	schema, prefix, ok := discoverMagentoSchema(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("Magento site")
	}
	table, err := QuoteIdent(prefix + "admin_user")
	if err != nil {
		return VerifyResult{Checked: false, Detail: "could not validate the Magento table from the finding"}
	}
	rows, err := runDBVerifyQueryRoot(schema,
		fmt.Sprintf("SELECT user_id FROM %s WHERE user_id = ?", table), id)
	return dbAdminPresenceResult(err, rows)
}

func verifyOpenCartAdminInjection(message, details string) VerifyResult {
	id, ok := dbAdminRowID(details)
	if !ok {
		return VerifyResult{Checked: false, Detail: "could not parse the account id from the finding"}
	}
	schema, prefix, ok := discoverOpenCartSchema(dbFindingAccount(message, details))
	if !ok {
		return dbVerifyNotLocatable("OpenCart site")
	}
	table, err := QuoteIdent(prefix + "user")
	if err != nil {
		return VerifyResult{Checked: false, Detail: "could not validate the OpenCart table from the finding"}
	}
	rows, err := runDBVerifyQueryRoot(schema,
		fmt.Sprintf("SELECT user_id FROM %s WHERE user_id = ?", table), id)
	return dbAdminPresenceResult(err, rows)
}
