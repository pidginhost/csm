package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
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
	default:
		return RemediationResult{Error: fmt.Sprintf("no automated fix available for check type '%s'", checkType)}
	}
}

// fixPermissions sets file permissions to 0644.
func fixPermissions(path string) RemediationResult {
	if path == "" {
		return RemediationResult{Error: "could not extract file path from finding"}
	}

	info, err := os.Stat(path)
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

	info, err := os.Stat(path)
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
	_ = os.WriteFile(qPath+".meta", metaData, 0600)

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
