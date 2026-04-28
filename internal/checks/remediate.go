package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// eximMsgIDRegex validates Exim message ID format (e.g., 2jKPFm-000abc-1X).
var eximMsgIDRegex = regexp.MustCompile(`^[0-9A-Za-z]{6}-[0-9A-Za-z]{6}-[0-9A-Za-z]{2}$`)

// Allowed roots for each fix action. Declared as vars (not consts) so tests
// can redirect remediation under t.TempDir() without writing to real /home,
// /tmp, or /var/spool. Production must not mutate these at runtime.
var (
	fixPermissionsAllowedRoots = []string{"/home"}
	fixQuarantineAllowedRoots  = []string{"/home", "/tmp", "/dev/shm", "/var/tmp"}
	fixHtaccessAllowedRoots    = []string{"/home"}
	eximSpoolDirs              = []string{"/var/spool/exim/input", "/var/spool/exim4/input"}
)

// RemediationResult describes the outcome of a fix action.
type RemediationResult struct {
	Success     bool   `json:"success"`
	Action      string `json:"action"`      // human-readable description of what was done
	Description string `json:"description"` // what fix was applied
	Error       string `json:"error,omitempty"`
}

// FixDescription returns a human-readable description of what the fix will do
// for a given check type and file path. Returns empty string if no fix is available.
func FixDescription(checkType, message string, filePath ...string) string {
	path := selectFindingPath(message, filePath...)

	switch checkType {
	case "world_writable_php", "group_writable_php":
		if path != "" {
			return fmt.Sprintf("Set permissions to 644 on %s", path)
		}
	case "webshell", "new_webshell_file", "obfuscated_php", "php_dropper",
		"suspicious_php_content", "new_php_in_languages", "new_php_in_upgrade",
		"phishing_page", "phishing_directory":
		if path != "" {
			return fmt.Sprintf("Quarantine %s to /opt/csm/quarantine/", path)
		}
	case "backdoor_binary", "new_executable_in_config":
		if path != "" {
			return fmt.Sprintf("Kill process and quarantine %s", path)
		}
	case "suspicious_crontab":
		if path != "" {
			return fmt.Sprintf("Quarantine and truncate crontab %s", path)
		}
		return "Quarantine and truncate crontab"
	case "htaccess_injection", "htaccess_handler_abuse",
		"htaccess_auto_prepend", "htaccess_errordocument_hijack",
		"htaccess_filesmatch_shield", "htaccess_header_injection",
		"htaccess_php_in_uploads", "htaccess_spam_redirect",
		"htaccess_user_agent_cloak":
		if path != "" {
			return fmt.Sprintf("Remove malicious directives from %s", path)
		}
	case "email_phishing_content":
		msgID := extractEximMsgID(message)
		if msgID != "" {
			return fmt.Sprintf("Quarantine Exim spool message %s", msgID)
		}
	}
	return ""
}

// HasFix returns true if the check type has a known automated fix.
func HasFix(checkType string) bool {
	fixableChecks := map[string]bool{
		"world_writable_php":       true,
		"group_writable_php":       true,
		"webshell":                 true,
		"new_webshell_file":        true,
		"obfuscated_php":           true,
		"php_dropper":              true,
		"suspicious_php_content":   true,
		"new_php_in_languages":     true,
		"new_php_in_upgrade":       true,
		"phishing_page":            true,
		"phishing_directory":       true,
		"backdoor_binary":          true,
		"new_executable_in_config": true,
		"htaccess_injection":       true,
		"htaccess_handler_abuse":   true,
		// Per-pattern findings from the hardened detectors. Each routes
		// through CleanHtaccessFile, which runs the full registry and
		// removes every detector's matched ranges atomically.
		"htaccess_auto_prepend":         true,
		"htaccess_errordocument_hijack": true,
		"htaccess_filesmatch_shield":    true,
		"htaccess_header_injection":     true,
		"htaccess_php_in_uploads":       true,
		"htaccess_spam_redirect":        true,
		"htaccess_user_agent_cloak":     true,
		"email_phishing_content":        true,
		"suspicious_crontab":            true,
	}
	return fixableChecks[checkType]
}

// ApplyFix executes the remediation action for a finding.
func ApplyFix(checkType, message, details string, filePath ...string) RemediationResult {
	path := selectFindingPath(message, filePath...)

	switch checkType {
	case "world_writable_php", "group_writable_php":
		return fixPermissions(path)
	case "webshell", "new_webshell_file", "obfuscated_php", "php_dropper",
		"suspicious_php_content", "new_php_in_languages", "new_php_in_upgrade",
		"phishing_page", "phishing_directory":
		return fixQuarantine(path)
	case "backdoor_binary", "new_executable_in_config":
		return fixKillAndQuarantine(path, details)
	case "htaccess_injection", "htaccess_handler_abuse":
		return fixHtaccess(path, message)
	case "htaccess_auto_prepend", "htaccess_errordocument_hijack",
		"htaccess_filesmatch_shield", "htaccess_header_injection",
		"htaccess_php_in_uploads", "htaccess_spam_redirect",
		"htaccess_user_agent_cloak":
		// Per-pattern findings emit alongside the generic
		// htaccess_injection / htaccess_handler_abuse categories from
		// the existing detector. Both routes converge on byte-range
		// cleaning here -- CleanHtaccessFile re-runs the full
		// detector registry, so a single click cleans every malicious
		// directive the audit found.
		return CleanHtaccessFile(path)
	case "email_phishing_content":
		return fixQuarantineSpoolMessage(message)
	case "suspicious_crontab":
		return fixSuspiciousCrontab(path)
	default:
		return RemediationResult{Error: fmt.Sprintf("no automated fix available for check type '%s'", checkType)}
	}
}

// fixPermissions sets file permissions to 0644.
func fixPermissions(path string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	path, info, err := resolveExistingFixPath(path, fixPermissionsAllowedRoots)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}

	oldMode := info.Mode().Perm()
	// #nosec G302 -- Intentional: this is the remediation that sets the
	// canonical "safe web content" mode on a user file after we flagged
	// the file as having dangerous perms (e.g. 0777). 0644 is what the
	// webserver needs to serve static content as the file owner.
	if err := os.Chmod(path, 0644); err != nil {
		return RemediationResult{Error: fmt.Sprintf("chmod failed: %v", err)}
	}

	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("chmod 644 %s", path),
		Description: fmt.Sprintf("Changed permissions from %o to 644", oldMode),
	}
}

// fixQuarantine moves a file or directory to quarantine.
func fixQuarantine(path string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	path, info, err := resolveExistingFixPath(path, fixQuarantineAllowedRoots)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}

	_ = os.MkdirAll(quarantineDir, 0700)
	safeName := strings.ReplaceAll(path, "/", "_")
	ts := time.Now().Format("20060102-150405")
	qPath := filepath.Join(quarantineDir, fmt.Sprintf("%s_%s", ts, safeName))

	if err := os.Rename(path, qPath); err != nil {
		// Cross-device fallback for files
		if !info.IsDir() {
			data, readErr := osFS.ReadFile(path)
			if readErr != nil {
				return RemediationResult{Error: fmt.Sprintf("cannot read file: %v", readErr)}
			}
			if writeErr := os.WriteFile(qPath, data, 0600); writeErr != nil {
				return RemediationResult{Error: fmt.Sprintf("cannot write quarantine: %v", writeErr)}
			}
			os.Remove(path)
		} else {
			return RemediationResult{Error: fmt.Sprintf("cannot quarantine directory: %v", err)}
		}
	}

	// Write metadata sidecar for restore
	var uid, gid int
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid = int(stat.Uid)
		gid = int(stat.Gid)
	}
	meta := map[string]interface{}{
		"original_path": path,
		"owner_uid":     uid,
		"group_gid":     gid,
		"mode":          info.Mode().String(),
		"size":          info.Size(),
		"quarantine_at": time.Now(),
		"reason":        "Fixed via CSM Web UI",
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(qPath+".meta", metaData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "remediate: error writing quarantine metadata %s: %v\n", qPath+".meta", err)
	}

	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("quarantined %s → %s", path, qPath),
		Description: fmt.Sprintf("Moved to quarantine: %s", qPath),
	}
}

// fixKillAndQuarantine kills any process using the file, then quarantines it.
func fixKillAndQuarantine(path, details string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	// Try to extract and kill PID from details
	pid := extractPID(details)
	if pid != "" {
		pidInt := 0
		fmt.Sscanf(pid, "%d", &pidInt)
		if pidInt > 1 {
			uid := getProcessUID(pid)
			if uid != "0" && uid != "" { // never kill root
				_ = syscall.Kill(pidInt, syscall.SIGKILL)
			}
		}
	}

	// Then quarantine
	result := fixQuarantine(path)
	if result.Success && pid != "" {
		result.Action = fmt.Sprintf("killed PID %s and %s", pid, result.Action)
		result.Description = "Process killed and file quarantined"
	}
	return result
}

// fixHtaccess removes malicious directives from an .htaccess file while
// preserving comments and known-safe directives (e.g., Wordfence, LiteSpeed).
func fixHtaccess(path, message string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path"}
	}
	if filepath.Base(path) != ".htaccess" {
		return RemediationResult{Error: "automated .htaccess remediation only applies to .htaccess files"}
	}
	path, _, err := resolveExistingFixPath(path, fixHtaccessAllowedRoots)
	if err != nil {
		return RemediationResult{Error: err.Error()}
	}
	data, err := osFS.ReadFile(path)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("cannot read: %v", err)}
	}

	dangerous := []string{"auto_prepend_file", "auto_append_file", "eval(", "base64_decode",
		"gzinflate", "str_rot13", "addhandler", "sethandler"}
	safe := []string{
		"wordfence-waf.php", "litespeed", "advanced-headers.php", "rsssl",
		"application/x-httpd-php", "application/x-httpd-ea-php", "application/x-httpd-alt-php",
		"-execcgi", "sethandler none", "sethandler default-handler",
		"text/html", "text/css", "text/javascript", "application/javascript",
		"image/", "font/", ".woff", ".woff2", ".ttf", ".eot", ".svg",
		"wordfence",
	}

	var cleaned []string
	removed := 0
	for _, line := range strings.Split(string(data), "\n") {
		lineLower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lineLower, "#") {
			cleaned = append(cleaned, line)
			continue
		}
		isDangerous := false
		for _, d := range dangerous {
			if strings.Contains(lineLower, d) {
				isSafe := false
				for _, s := range safe {
					if strings.Contains(lineLower, s) {
						isSafe = true
						break
					}
				}
				if !isSafe {
					isDangerous = true
					break
				}
			}
		}
		if isDangerous {
			removed++
		} else {
			cleaned = append(cleaned, line)
		}
	}

	if removed == 0 {
		return RemediationResult{Error: "no malicious directives found to remove"}
	}

	// #nosec G306 -- .htaccess rewritten for a user's public_html; 0644 is
	// the mode the webserver expects for static content.
	if err := os.WriteFile(path, []byte(strings.Join(cleaned, "\n")), 0644); err != nil {
		return RemediationResult{Error: fmt.Sprintf("write failed: %v", err)}
	}
	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("removed %d malicious directive(s) from %s", removed, path),
		Description: fmt.Sprintf("Cleaned .htaccess: removed %d line(s)", removed),
	}
}

// extractFilePathFromMessage extracts a file path from a finding message.
// Handles patterns like "World-writable PHP file: /path/to/file"
// and "Webshell found: /path/to/file"
func extractFilePathFromMessage(message string) string {
	// Look for /home/ or /tmp/ paths
	for _, prefix := range []string{"/home/", "/tmp/", "/dev/shm/", "/var/tmp/"} {
		idx := strings.Index(message, prefix)
		if idx < 0 {
			continue
		}
		rest := message[idx:]
		// Path ends at space, comma, newline, or end
		endIdx := len(rest)
		for i, c := range rest {
			if c == ' ' || c == ',' || c == '\n' || c == ')' {
				endIdx = i
				break
			}
		}
		return rest[:endIdx]
	}
	return ""
}

func selectFindingPath(message string, filePath ...string) string {
	if len(filePath) > 0 {
		if path := strings.TrimSpace(filePath[0]); path != "" {
			return path
		}
	}
	return extractFilePathFromMessage(message)
}

func resolveExistingFixPath(path string, allowedRoots []string) (string, os.FileInfo, error) {
	cleanPath, err := sanitizeFixPath(path, allowedRoots)
	if err != nil {
		return "", nil, err
	}

	info, err := osFS.Lstat(cleanPath)
	if err != nil {
		return "", nil, fmt.Errorf("file not found: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", nil, fmt.Errorf("symlinked paths are not eligible for automated remediation: %s", cleanPath)
	}

	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err != nil {
		return "", nil, fmt.Errorf("cannot resolve path: %v", err)
	}
	resolved, err = sanitizeFixPath(resolved, allowedRoots)
	if err != nil {
		return "", nil, err
	}
	if accountRoot := homeAccountRoot(cleanPath); accountRoot != "" && !isPathWithinOrEqual(resolved, accountRoot) {
		return "", nil, fmt.Errorf("resolved path escapes account boundary: %s", resolved)
	}

	resolvedInfo, err := osFS.Lstat(resolved)
	if err != nil {
		return "", nil, fmt.Errorf("file not found: %v", err)
	}
	if resolvedInfo.Mode()&os.ModeSymlink != 0 {
		return "", nil, fmt.Errorf("symlinked paths are not eligible for automated remediation: %s", resolved)
	}

	return resolved, resolvedInfo, nil
}

func sanitizeFixPath(path string, allowedRoots []string) (string, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" {
		return "", fmt.Errorf("file path is required")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("file path must be absolute")
	}
	for _, root := range allowedRoots {
		if isPathWithinOrEqual(path, root) {
			return path, nil
		}
	}
	return "", fmt.Errorf("file path is outside the allowed remediation roots: %s", path)
}

func isPathWithinOrEqual(path, base string) bool {
	cleanPath := filepath.Clean(path)
	cleanBase := filepath.Clean(base)
	return cleanPath == cleanBase || strings.HasPrefix(cleanPath, cleanBase+string(filepath.Separator))
}

func homeAccountRoot(path string) string {
	clean := filepath.Clean(path)
	if !strings.HasPrefix(clean, "/home/") {
		return ""
	}
	parts := strings.Split(clean, string(filepath.Separator))
	if len(parts) < 4 {
		return ""
	}
	return filepath.Join("/home", parts[2])
}

// extractEximMsgID extracts an Exim message ID from a finding message.
// Matches the pattern "(message: XXXXXX-XXXXXX-XX)" used by emailscan.go.
func extractEximMsgID(message string) string {
	prefix := "(message: "
	idx := strings.Index(message, prefix)
	if idx < 0 {
		return ""
	}
	rest := message[idx+len(prefix):]
	end := strings.Index(rest, ")")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}

// fixQuarantineSpoolMessage moves Exim spool files (-H header and -D body)
// for a message ID into quarantine.
func fixQuarantineSpoolMessage(message string) RemediationResult {
	msgID := extractEximMsgID(message)
	if msgID == "" {
		return RemediationResult{Error: "could not extract Exim message ID from finding"}
	}
	// Validate Exim message ID format to prevent path traversal
	if !eximMsgIDRegex.MatchString(msgID) {
		return RemediationResult{Error: fmt.Sprintf("invalid Exim message ID format: %s", msgID)}
	}

	var spoolDir string
	for _, dir := range eximSpoolDirs {
		if _, err := osFS.Stat(filepath.Join(dir, msgID+"-H")); err == nil {
			spoolDir = dir
			break
		}
	}
	if spoolDir == "" {
		return RemediationResult{Error: fmt.Sprintf("spool message %s not found (already delivered or removed)", msgID)}
	}

	_ = os.MkdirAll(quarantineDir, 0700)
	ts := time.Now().Format("20060102-150405")
	moved := 0

	for _, suffix := range []string{"-H", "-D"} {
		src := filepath.Join(spoolDir, msgID+suffix)
		if _, err := osFS.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(quarantineDir, fmt.Sprintf("%s_exim_%s%s", ts, msgID, suffix))
		if err := os.Rename(src, dst); err != nil {
			// Cross-device fallback
			data, readErr := osFS.ReadFile(src)
			if readErr != nil {
				return RemediationResult{Error: fmt.Sprintf("cannot read %s: %v", src, readErr)}
			}
			if writeErr := os.WriteFile(dst, data, 0600); writeErr != nil {
				return RemediationResult{Error: fmt.Sprintf("cannot write quarantine: %v", writeErr)}
			}
			os.Remove(src)
		}
		moved++
	}

	if moved == 0 {
		return RemediationResult{Error: fmt.Sprintf("no spool files found for message %s", msgID)}
	}

	// Write metadata sidecar
	meta := map[string]interface{}{
		"message_id":    msgID,
		"spool_dir":     spoolDir,
		"quarantine_at": time.Now(),
		"reason":        "Phishing email quarantined via CSM Web UI",
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	metaPath := filepath.Join(quarantineDir, fmt.Sprintf("%s_exim_%s.meta", ts, msgID))
	if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "remediate: error writing spool quarantine metadata %s: %v\n", metaPath, err)
	}

	return RemediationResult{
		Success:     true,
		Action:      fmt.Sprintf("quarantined spool message %s (%d files)", msgID, moved),
		Description: fmt.Sprintf("Exim spool files moved to quarantine for message %s", msgID),
	}
}
