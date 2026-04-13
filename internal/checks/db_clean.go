package checks

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// DBCleanResult describes the outcome of a database cleanup operation.
type DBCleanResult struct {
	Account     string
	Database    string
	Action      string // "clean-option", "revoke-user", "delete-spam"
	Success     bool
	Message     string
	Details     []string // individual actions taken
	BackupNames []string // names of backup options created
}

// DBCleanOption removes malicious script injections from a wp_option value.
// Creates a backup option before modifying. Returns a result describing
// what was done. If preview is true, reports what would be done without
// modifying the database.
func DBCleanOption(account, optionName string, preview bool) DBCleanResult {
	result := DBCleanResult{
		Account: account,
		Action:  "clean-option",
	}

	if !isValidOptionName(optionName) {
		result.Message = fmt.Sprintf("Invalid option name: %q", optionName)
		return result
	}

	creds, prefix := findCredsForAccount(account)
	if creds.dbName == "" {
		result.Message = fmt.Sprintf("No WordPress database found for account %q", account)
		return result
	}
	result.Database = creds.dbName

	// Read current value.
	value := readOptionValue(creds, prefix, optionName)
	if value == "" {
		result.Message = fmt.Sprintf("Option %q not found or empty in %s", optionName, creds.dbName)
		return result
	}

	// Check for malicious content.
	maliciousURL := extractMaliciousScriptURL(value)
	if maliciousURL == "" {
		result.Message = fmt.Sprintf("No malicious external script found in %q", optionName)
		result.Details = append(result.Details, "Option exists but contains no confirmed malicious URLs")
		return result
	}

	cleaned := removeMaliciousScripts(value)
	if cleaned == value {
		result.Message = "Content unchanged after cleaning"
		return result
	}

	result.Details = append(result.Details, fmt.Sprintf("Malicious URL: %s", maliciousURL))
	result.Details = append(result.Details, fmt.Sprintf("Original length: %d, Cleaned length: %d", len(value), len(cleaned)))

	if preview {
		result.Message = fmt.Sprintf("PREVIEW: Would clean malicious script from %q", optionName)
		result.Success = true
		return result
	}

	// Backup and clean.
	if backupAndCleanOption(creds, prefix, optionName, value, maliciousURL) {
		backupName := fmt.Sprintf("csm_backup_%s_%d", optionName, time.Now().Unix())
		if len(backupName) > 191 {
			backupName = backupName[:191]
		}
		result.BackupNames = append(result.BackupNames, backupName)
		result.Details = append(result.Details, fmt.Sprintf("Backup saved as: %s", backupName))
		result.Message = fmt.Sprintf("Cleaned malicious script from %q", optionName)
		result.Success = true
	} else {
		result.Message = "Failed to clean option"
	}

	return result
}

// DBRevokeUser revokes WordPress sessions for a specific user and optionally
// demotes them to subscriber role. If preview is true, reports what would be
// done without modifying the database.
func DBRevokeUser(account string, userID int, demote, preview bool) DBCleanResult {
	result := DBCleanResult{
		Account: account,
		Action:  "revoke-user",
	}

	creds, prefix := findCredsForAccount(account)
	if creds.dbName == "" {
		result.Message = fmt.Sprintf("No WordPress database found for account %q", account)
		return result
	}
	result.Database = creds.dbName

	// Verify user exists.
	query := fmt.Sprintf(
		"SELECT user_login, user_email FROM %susers WHERE ID=%d LIMIT 1",
		prefix, userID)
	lines := runMySQLQueryRoot(creds.dbName, query)
	if len(lines) == 0 {
		result.Message = fmt.Sprintf("User ID %d not found in %s", userID, creds.dbName)
		return result
	}

	parts := strings.SplitN(lines[0], "\t", 2)
	login := parts[0]
	email := ""
	if len(parts) > 1 {
		email = parts[1]
	}
	result.Details = append(result.Details, fmt.Sprintf("User: %s (email: %s)", login, email))

	// Check current sessions.
	sessQuery := fmt.Sprintf(
		"SELECT LEFT(meta_value, 200) FROM %susermeta WHERE user_id=%d AND meta_key='session_tokens'",
		prefix, userID)
	sessLines := runMySQLQueryRoot(creds.dbName, sessQuery)
	sessionCount := 0
	if len(sessLines) > 0 && sessLines[0] != "" {
		sessionCount = strings.Count(sessLines[0], `"expiration"`)
	}
	result.Details = append(result.Details, fmt.Sprintf("Active sessions: %d", sessionCount))

	if preview {
		msg := fmt.Sprintf("PREVIEW: Would revoke %d sessions for user %s (ID %d)", sessionCount, login, userID)
		if demote {
			msg += " and demote to subscriber"
		}
		result.Message = msg
		result.Success = true
		return result
	}

	// Revoke sessions.
	revokeQuery := fmt.Sprintf(
		"UPDATE %susermeta SET meta_value='' WHERE user_id=%d AND meta_key='session_tokens'",
		prefix, userID)
	runMySQLQueryRoot(creds.dbName, revokeQuery)
	result.Details = append(result.Details, "Sessions revoked")

	// Demote to subscriber.
	if demote {
		// Read current capabilities to find the meta_key (varies by prefix).
		capQuery := fmt.Sprintf(
			"SELECT meta_key FROM %susermeta WHERE user_id=%d AND meta_key LIKE '%%capabilities'",
			prefix, userID)
		capLines := runMySQLQueryRoot(creds.dbName, capQuery)
		if len(capLines) > 0 {
			capKey := capLines[0]
			demoteQuery := fmt.Sprintf(
				"UPDATE %susermeta SET meta_value='a:1:{s:10:\"subscriber\";b:1;}' WHERE user_id=%d AND meta_key='%s'",
				prefix, userID, escapeSQLString(capKey))
			runMySQLQueryRoot(creds.dbName, demoteQuery)
			result.Details = append(result.Details, "Demoted to subscriber role")
		}
	}

	result.Message = fmt.Sprintf("Revoked sessions for user %s (ID %d)", login, userID)
	result.Success = true
	return result
}

// DBDeleteSpam deletes published posts matching spam patterns from a WordPress
// database. Only deletes posts of type 'post' with status 'publish' to avoid
// touching pages, attachments, or plugin data. If preview is true, reports
// counts without deleting.
func DBDeleteSpam(account string, preview bool) DBCleanResult {
	result := DBCleanResult{
		Account: account,
		Action:  "delete-spam",
	}

	creds, prefix := findCredsForAccount(account)
	if creds.dbName == "" {
		result.Message = fmt.Sprintf("No WordPress database found for account %q", account)
		return result
	}
	result.Database = creds.dbName

	// Count spam posts by pattern.
	patterns := []struct {
		keyword string
		sqlLike string
	}{
		{"casino", "%casino-%"},
		{"betting", "%betting%"},
		{"cialis", "%cialis%"},
		{"viagra", "%viagra%"},
		{"pharma", "%pharma%"},
		{"buy-cheap", "%buy-cheap-%"},
		{"crack-serial", "%crack-serial%"},
		{"free-download", "%free-download%"},
	}

	totalCount := 0
	for _, p := range patterns {
		countQuery := "SELECT COUNT(*) FROM " + prefix + "posts WHERE post_type='post' AND post_status='publish' AND (post_content LIKE '" + p.sqlLike + "' OR post_title LIKE '" + p.sqlLike + "')"
		lines := runMySQLQueryRoot(creds.dbName, countQuery)
		if len(lines) > 0 {
			var count int
			if _, err := fmt.Sscanf(lines[0], "%d", &count); err == nil && count > 0 {
				result.Details = append(result.Details, fmt.Sprintf("%s: %d posts", p.keyword, count))
				totalCount += count
			}
		}
	}

	if totalCount == 0 {
		result.Message = "No spam posts found"
		result.Success = true
		return result
	}

	if preview {
		result.Message = fmt.Sprintf("PREVIEW: Would delete up to %d spam posts", totalCount)
		result.Success = true
		return result
	}

	// Delete spam posts (and their revisions/meta).
	deleted := 0
	for _, p := range patterns {
		// Get IDs of matching posts.
		idQuery := "SELECT ID FROM " + prefix + "posts WHERE post_type='post' AND post_status='publish' AND (post_content LIKE '" + p.sqlLike + "' OR post_title LIKE '" + p.sqlLike + "')"
		idLines := runMySQLQueryRoot(creds.dbName, idQuery)
		if len(idLines) == 0 {
			continue
		}

		// Delete in batches of 100.
		for i := 0; i < len(idLines); i += 100 {
			end := i + 100
			if end > len(idLines) {
				end = len(idLines)
			}
			batch := idLines[i:end]

			// Validate IDs are numeric.
			var validIDs []string
			idRe := regexp.MustCompile(`^\d+$`)
			for _, id := range batch {
				id = strings.TrimSpace(id)
				if idRe.MatchString(id) {
					validIDs = append(validIDs, id)
				}
			}
			if len(validIDs) == 0 {
				continue
			}

			idList := strings.Join(validIDs, ",")

			// Delete postmeta for these posts.
			runMySQLQueryRoot(creds.dbName, fmt.Sprintf(
				"DELETE FROM %spostmeta WHERE post_id IN (%s)", prefix, idList))

			// Delete revisions.
			runMySQLQueryRoot(creds.dbName, fmt.Sprintf(
				"DELETE FROM %sposts WHERE post_parent IN (%s) AND post_type='revision'",
				prefix, idList))

			// Delete the posts themselves.
			runMySQLQueryRoot(creds.dbName, fmt.Sprintf(
				"DELETE FROM %sposts WHERE ID IN (%s) AND post_type='post' AND post_status='publish'",
				prefix, idList))

			deleted += len(validIDs)
		}
	}

	result.Message = fmt.Sprintf("Deleted %d spam posts and their metadata", deleted)
	result.Success = true
	return result
}

// FormatDBCleanResult formats a DBCleanResult for terminal output.
func FormatDBCleanResult(r DBCleanResult) string {
	var sb strings.Builder

	status := "FAILED"
	if r.Success {
		status = "OK"
	}

	fmt.Fprintf(&sb, "[%s] %s — %s\n", status, r.Action, r.Message)
	if r.Database != "" {
		fmt.Fprintf(&sb, "  Database: %s\n", r.Database)
	}
	for _, d := range r.Details {
		fmt.Fprintf(&sb, "  %s\n", d)
	}

	return sb.String()
}

// --- helpers ---

// findCredsForAccount finds WP database credentials for a cPanel account.
// Returns root-authenticated credentials that use /root/.my.cnf instead of
// wp-config.php passwords (which are often stale on cPanel servers).
func findCredsForAccount(account string) (wpDBCreds, string) {
	patterns := []string{
		fmt.Sprintf("/home/%s/public_html/wp-config.php", account),
	}
	addonConfigs, _ := osFS.Glob(fmt.Sprintf("/home/%s/*/wp-config.php", account))
	patterns = append(patterns, addonConfigs...)

	for _, path := range patterns {
		creds := parseWPConfig(path)
		if creds.dbName != "" {
			prefix := creds.tablePrefix
			if prefix == "" {
				prefix = "wp_"
			}
			// Use root auth — CSM runs as root with /root/.my.cnf.
			// wp-config.php passwords are unreliable (cPanel password
			// rotations don't always update the file).
			creds.dbUser = ""
			creds.dbPass = ""
			creds.dbHost = "localhost"
			return creds, prefix
		}
	}
	return wpDBCreds{}, ""
}

// runMySQLQueryRoot runs a MySQL query using root credentials from
// /root/.my.cnf (no explicit user/password args).
func runMySQLQueryRoot(dbName, query string) []string {
	args := []string{
		"-N", "-B",
		dbName,
		"-e", query,
	}
	out, err := runCmd("mysql", args...)
	if err != nil || out == nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
