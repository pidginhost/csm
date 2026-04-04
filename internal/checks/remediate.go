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

// RemediationResult describes the outcome of a fix action.
type RemediationResult struct {
	Success     bool   `json:"success"`
	Action      string `json:"action"`      // human-readable description of what was done
	Description string `json:"description"` // what fix was applied
	Error       string `json:"error,omitempty"`
}

// FixDescription returns a human-readable description of what the fix will do
// for a given check type and file path. Returns empty string if no fix is available.
func FixDescription(checkType, message string) string {
	path := extractFilePathFromMessage(message)

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
		return "Remove suspicious lines from crontab"
	case "htaccess_injection", "htaccess_handler_abuse":
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
		"email_phishing_content":   true,
	}
	return fixableChecks[checkType]
}

// ApplyFix executes the remediation action for a finding.
func ApplyFix(checkType, message, details string) RemediationResult {
	path := extractFilePathFromMessage(message)

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
	case "email_phishing_content":
		return fixQuarantineSpoolMessage(message)
	default:
		return RemediationResult{Error: fmt.Sprintf("no automated fix available for check type '%s'", checkType)}
	}
}

// fixPermissions sets file permissions to 0644.
func fixPermissions(path string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	// Resolve symlinks to prevent TOCTOU race via symlink substitution
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("file not found: %v", err)}
	}
	if resolved != path {
		if !strings.HasPrefix(resolved, "/home/") {
			return RemediationResult{Error: fmt.Sprintf("symlink %s points outside /home/: %s, skipping", path, resolved)}
		}
		fmt.Fprintf(os.Stderr, "warning: remediation path %s resolved to %s via symlink\n", path, resolved)
	}
	path = resolved

	info, err := os.Lstat(path)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("file not found: %v", err)}
	}

	oldMode := info.Mode().Perm()
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

	// Resolve symlinks to prevent TOCTOU race via symlink substitution
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("file not found: %v", err)}
	}
	if resolved != path {
		if !strings.HasPrefix(resolved, "/home/") {
			return RemediationResult{Error: fmt.Sprintf("symlink %s points outside /home/: %s, skipping", path, resolved)}
		}
		fmt.Fprintf(os.Stderr, "warning: remediation path %s resolved to %s via symlink\n", path, resolved)
	}
	path = resolved

	info, err := os.Lstat(path)
	if err != nil {
		return RemediationResult{Error: fmt.Sprintf("file not found: %v", err)}
	}

	_ = os.MkdirAll(quarantineDir, 0700)
	safeName := strings.ReplaceAll(path, "/", "_")
	ts := time.Now().Format("20060102-150405")
	qPath := filepath.Join(quarantineDir, fmt.Sprintf("%s_%s", ts, safeName))

	if err := os.Rename(path, qPath); err != nil {
		// Cross-device fallback for files
		if !info.IsDir() {
			data, readErr := os.ReadFile(path)
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
	data, err := os.ReadFile(path)
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

	spoolDirs := []string{"/var/spool/exim/input", "/var/spool/exim4/input"}
	var spoolDir string
	for _, dir := range spoolDirs {
		if _, err := os.Stat(filepath.Join(dir, msgID+"-H")); err == nil {
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
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(quarantineDir, fmt.Sprintf("%s_exim_%s%s", ts, msgID, suffix))
		if err := os.Rename(src, dst); err != nil {
			// Cross-device fallback
			data, readErr := os.ReadFile(src)
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
