package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// var (not const) so tests can redirect to t.TempDir().
var quarantineDir = "/opt/csm/quarantine"

// QuarantineMeta stores original file metadata alongside quarantined files.
type QuarantineMeta struct {
	OriginalPath string    `json:"original_path"`
	Owner        int       `json:"owner_uid"`
	Group        int       `json:"group_gid"`
	Mode         string    `json:"mode"`
	Size         int64     `json:"size"`
	QuarantineAt time.Time `json:"quarantined_at"`
	Reason       string    `json:"reason"`
}

// AutoKillProcesses kills processes that match critical findings.
// Only targets: fake kernel threads, reverse shells, GSocket processes.
// Never kills root system services or cPanel processes.
func AutoKillProcesses(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	if !cfg.AutoResponse.Enabled || !cfg.AutoResponse.KillProcesses {
		return nil
	}

	var actions []alert.Finding

	for _, f := range findings {
		// Only act on specific high-confidence critical checks
		switch f.Check {
		case "fake_kernel_thread", "suspicious_process", "php_suspicious_execution":
		default:
			continue
		}
		if f.Severity != alert.Critical {
			continue
		}

		// Use structured PID field when available, fall back to text extraction
		pid := fmt.Sprintf("%d", f.PID)
		if f.PID == 0 {
			pid = extractPID(f.Details)
			if pid == "" {
				continue
			}
		}

		// Safety: verify the process is not root/system
		uid := getProcessUID(pid)
		if uid == "0" || uid == "" {
			continue // never kill root processes automatically
		}

		// Safety: verify it's not a cPanel/system process
		exe := getProcessExe(pid)
		if isSafeProcess(exe) {
			continue
		}

		// Kill it
		pidInt := f.PID
		if pidInt == 0 {
			fmt.Sscanf(pid, "%d", &pidInt)
		}
		if pidInt <= 1 {
			continue
		}

		err := syscall.Kill(pidInt, syscall.SIGKILL)
		if err != nil {
			continue
		}

		actions = append(actions, alert.Finding{
			Severity: alert.Critical,
			Check:    "auto_response",
			Message:  fmt.Sprintf("AUTO-KILL: Process %s killed (was: %s)", pid, f.Check),
			Details:  fmt.Sprintf("Original finding: %s\nProcess: %s (UID: %s)", f.Message, exe, uid),
		})
	}

	return actions
}

// AutoQuarantineFiles moves malicious files to quarantine directory.
// Preserves original path and metadata in a sidecar .meta file.
func AutoQuarantineFiles(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	if !cfg.AutoResponse.Enabled || !cfg.AutoResponse.QuarantineFiles {
		return nil
	}

	var actions []alert.Finding

	for _, f := range findings {
		// Only quarantine specific file-based findings
		isRealtimeMatch := false
		switch f.Check {
		case "webshell", "backdoor_binary", "new_webshell_file", "new_executable_in_config",
			"obfuscated_php", "php_dropper", "suspicious_php_content",
			"new_php_in_languages", "new_php_in_upgrade",
			"phishing_page", "phishing_directory",
			"htaccess_handler_abuse":
		case "signature_match_realtime":
			isRealtimeMatch = true
		default:
			continue
		}
		if f.Severity != alert.Critical {
			continue
		}

		// Extract file path - prefer structured field, fallback to message parsing
		path := f.FilePath
		if path == "" {
			path = extractFilePath(f.Message) // fallback for legacy findings
		}
		if path == "" {
			continue
		}

		// Realtime signature matches require additional validation to avoid
		// quarantining false positives (e.g. legitimate PHPMailer matching
		// "webshell_marijuana", or zip libraries matching hex patterns).
		// Only quarantine when the file is genuinely obfuscated malware.
		if isRealtimeMatch && !isHighConfidenceRealtimeMatch(f, path, nil) {
			continue
		}

		// Verify file or directory exists and reject symlinks
		info, err := osFS.Lstat(path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}

		// Realtime high-confidence matches are fully obfuscated malware -
		// there is no legitimate code to preserve, skip cleaning and go
		// straight to quarantine.
		if isRealtimeMatch {
			goto quarantine
		}

		// For WP core/plugin/theme files: clean surgically instead of quarantining.
		// This preserves site functionality while removing the injected code.
		if !info.IsDir() && ShouldCleanInsteadOfQuarantine(path) {
			result := CleanInfectedFile(path)
			switch {
			case result.Cleaned:
				actions = append(actions, alert.Finding{
					Severity:  alert.Critical,
					Check:     "auto_response",
					Message:   fmt.Sprintf("AUTO-CLEAN: %s surgically cleaned", path),
					Details:   fmt.Sprintf("Backup: %s\n%s", result.BackupPath, strings.Join(result.Removals, "\n")),
					Timestamp: time.Now(),
				})
				continue // successfully cleaned, skip quarantine
			case result.Error != "":
				// Cleaning failed - fall through to quarantine
				actions = append(actions, alert.Finding{
					Severity:  alert.Warning,
					Check:     "auto_response",
					Message:   fmt.Sprintf("AUTO-CLEAN failed for %s, quarantining instead", path),
					Details:   result.Error,
					Timestamp: time.Now(),
				})
				// Don't continue - fall through to quarantine below
			default:
				continue // no changes needed
			}
		}

	quarantine:
		// Create quarantine directory
		_ = os.MkdirAll(quarantineDir, 0700)

		// Build quarantine destination preserving directory structure
		safeName := strings.ReplaceAll(path, "/", "_")
		ts := time.Now().Format("20060102-150405")
		qPath := filepath.Join(quarantineDir, fmt.Sprintf("%s_%s", ts, safeName))

		// Get file ownership
		var uid, gid int
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			uid = int(stat.Uid)
			gid = int(stat.Gid)
		}

		// Handle directory quarantine (e.g., LEVIATHAN/ webshell directories)
		if info.IsDir() {
			if err := os.Rename(path, qPath); err != nil {
				// Cross-device: skip directory move (too complex for auto-response)
				continue
			}
		} else {
			// Move file to quarantine
			if err := os.Rename(path, qPath); err != nil {
				// If rename fails (cross-device), copy and delete
				data, readErr := osFS.ReadFile(path)
				if readErr != nil {
					continue
				}
				if writeErr := os.WriteFile(qPath, data, 0600); writeErr != nil {
					continue
				}
				if rmErr := os.Remove(path); rmErr != nil {
					// Remove failed - delete the copy to avoid duplication
					os.Remove(qPath)
					fmt.Fprintf(os.Stderr, "autoresponse: cross-device quarantine failed, cannot remove original %s: %v\n", path, rmErr)
					continue
				}
			}
		}

		// Write metadata sidecar
		meta := QuarantineMeta{
			OriginalPath: path,
			Owner:        uid,
			Group:        gid,
			Mode:         info.Mode().String(),
			Size:         info.Size(),
			QuarantineAt: time.Now(),
			Reason:       f.Message,
		}
		metaData, _ := json.MarshalIndent(meta, "", "  ")
		_ = os.WriteFile(qPath+".meta", metaData, 0600)

		actions = append(actions, alert.Finding{
			Severity: alert.Critical,
			Check:    "auto_response",
			Message:  fmt.Sprintf("AUTO-QUARANTINE: %s moved to quarantine", path),
			Details:  fmt.Sprintf("Quarantined to: %s\nOriginal finding: %s", qPath, f.Message),
		})
	}

	return actions
}

// AutoFixPermissions sets world/group-writable PHP files to 0644.
// Returns the auto-response action findings and the keys of original findings
// that were successfully fixed (so the caller can dismiss them from the UI).
func AutoFixPermissions(cfg *config.Config, findings []alert.Finding) (actions []alert.Finding, fixedKeys []string) {
	if !cfg.AutoResponse.Enabled || !cfg.AutoResponse.EnforcePermissions {
		return nil, nil
	}

	for _, f := range findings {
		switch f.Check {
		case "world_writable_php", "group_writable_php":
		default:
			continue
		}

		path := extractFilePath(f.Message)
		if path == "" {
			continue
		}

		path, info, err := resolveExistingFixPath(path, fixPermissionsAllowedRoots)
		if err != nil || info.IsDir() {
			continue
		}

		oldMode := info.Mode().Perm()
		// #nosec G302 -- same as fixPermissions: restoring canonical web-content
		// mode on a user file flagged for dangerous (e.g. world-writable) perms.
		if err := os.Chmod(path, 0644); err != nil {
			continue
		}

		actions = append(actions, alert.Finding{
			Severity:  alert.Warning,
			Check:     "auto_response",
			Message:   fmt.Sprintf("AUTO-FIX: %s permissions set to 644 (was %o)", path, oldMode),
			Timestamp: time.Now(),
		})
		fixedKeys = append(fixedKeys, f.Check+":"+f.Message)
	}

	return actions, fixedKeys
}

func extractPID(details string) string {
	// Look for "PID: 12345" pattern. Stop at the first whitespace, comma,
	// or newline so a trailing word ("PID: 42 exe=/bin/ls") doesn't get
	// returned as part of the PID string.
	idx := strings.Index(details, "PID: ")
	if idx < 0 {
		return ""
	}
	rest := details[idx+5:]
	for i, c := range rest {
		if c == ' ' || c == ',' || c == '\n' || c == '\t' {
			return strings.TrimSpace(rest[:i])
		}
	}
	return strings.TrimSpace(rest)
}

func extractFilePath(message string) string {
	// Look for /home/... or /tmp/... paths in the message. Order matters:
	// longer/more-specific prefixes (/var/tmp/, /dev/shm/) must come BEFORE
	// shorter ones (/tmp/) — otherwise "/tmp/" would match inside "/var/tmp/"
	// and we'd silently misclassify the path.
	for _, prefix := range []string{"/var/tmp/", "/dev/shm/", "/home/", "/tmp/"} {
		if idx := strings.Index(message, prefix); idx >= 0 {
			rest := message[idx:]
			// Path ends at space, comma, or end of string
			endIdx := len(rest)
			for i, c := range rest {
				if c == ' ' || c == ',' || c == '\n' {
					endIdx = i
					break
				}
			}
			return rest[:endIdx]
		}
	}
	return ""
}

func getProcessUID(pid string) string {
	data, err := osFS.ReadFile(filepath.Join("/proc", pid, "status"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:\t") {
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:\t"))
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}

func getProcessExe(pid string) string {
	exe, err := osFS.Readlink(filepath.Join("/proc", pid, "exe"))
	if err != nil {
		return ""
	}
	return exe
}

func isSafeProcess(exe string) bool {
	safePrefixes := []string{
		"/usr/local/cpanel/",
		"/usr/sbin/",
		"/usr/bin/",
		"/usr/libexec/",
		"/opt/cpanel/",
		"/opt/cloudlinux/",
		"/opt/imunify360/",
	}
	for _, prefix := range safePrefixes {
		if strings.HasPrefix(exe, prefix) {
			return true
		}
	}
	return false
}

// isHighConfidenceRealtimeMatch validates whether a realtime signature match
// is truly malicious and safe to auto-quarantine. Prevents false positives
// on legitimate libraries (PHPMailer, zip) and theme code.
//
// The data parameter should be the file content already read by the caller
// (fanotify fd or scanner) to avoid TOCTOU re-reads. Pass nil to read from path.
//
// Criteria:
//  1. Category must be "dropper" or "webshell"
//  2. File must not be in a known library path
//  3. File must be >= 512 bytes (entropy unreliable below this)
//  4. Content must show obfuscation indicators:
//     Shannon entropy >= 4.8 OR hex density > 20%.
//     This applies to BOTH dropper and webshell categories to avoid
//     false-positive quarantine of legitimate plugins that happen to
//     match a dropper rule (e.g. curl_exec + eval on distant lines).
func isHighConfidenceRealtimeMatch(f alert.Finding, path string, data []byte) bool {
	cat := extractCategory(f.Details)
	switch cat {
	case "dropper", "webshell":
	default:
		return false
	}

	pathLower := strings.ToLower(path)
	for _, lib := range knownLibraryPaths {
		if strings.Contains(pathLower, lib) {
			return false
		}
	}

	if data == nil {
		var err error
		data, err = osFS.ReadFile(path)
		if err != nil {
			return false
		}
	}

	if len(data) < 512 {
		return false
	}

	// Both dropper and webshell categories go through the same entropy/encoding
	// checks to avoid false positives. Legitimate plugins (low entropy ~4.2)
	// pass through, while real obfuscated malware (high entropy ~5.5+) or
	// hex-heavy payloads still get quarantined.
	content := string(data)
	return shannonEntropy(content) >= 4.8 || hexEncodingDensity(content) > 0.20
}

// hexEncodingDensity returns the fraction of a string's bytes that are part
// of PHP hex escape sequences (\xNN). LEVIATHAN AES-encrypted webshells
// encode their payload as long hex strings - the \x prefix repeats so
// frequently that Shannon entropy drops to ~3.5 (below normal PHP), but
// the hex density reaches 40-60%.
func hexEncodingDensity(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	hexBytes := 0
	for i := 0; i < len(s)-3; i++ {
		if s[i] == '\\' && s[i+1] == 'x' &&
			isHexDigit(s[i+2]) && isHexDigit(s[i+3]) {
			hexBytes += 4
			i += 3 // skip past this sequence
		}
	}
	return float64(hexBytes) / float64(len(s))
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// knownLibraryPaths are directory fragments that indicate a file belongs to
// a well-known third-party library and should never be auto-quarantined.
var knownLibraryPaths = []string{
	"/phpmailer/",
	"/vendor/",
	"/node_modules/",
	"/pear/",
	"/tcpdf/",
	"/dompdf/",
	"/guzzlehttp/",
	"/symfony/",
	"/monolog/",
}

// InlineQuarantine moves a file to quarantine immediately if it passes the
// high-confidence validation gates. Called from fanotify's analyzeFile to
// quarantine malware without waiting for the 5-second batch dispatcher.
// The data parameter is the file content already read by the caller (avoids
// TOCTOU re-read). Pass nil to read from path.
// Returns the quarantine path and true if the file was quarantined.
func InlineQuarantine(f alert.Finding, path string, data []byte) (string, bool) {
	if !isHighConfidenceRealtimeMatch(f, path, data) {
		return "", false
	}

	info, err := osFS.Stat(path)
	if err != nil {
		return "", false
	}

	_ = os.MkdirAll(quarantineDir, 0700)
	safeName := strings.ReplaceAll(path, "/", "_")
	ts := time.Now().Format("20060102-150405")
	qPath := filepath.Join(quarantineDir, fmt.Sprintf("%s_%s", ts, safeName))

	if err := os.Rename(path, qPath); err != nil {
		if info.IsDir() {
			return "", false
		}
		data, readErr := osFS.ReadFile(path)
		if readErr != nil {
			return "", false
		}
		if writeErr := os.WriteFile(qPath, data, 0600); writeErr != nil {
			return "", false
		}
		os.Remove(path)
	}

	// Write metadata sidecar
	var uid, gid int
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid = int(stat.Uid)
		gid = int(stat.Gid)
	}
	meta := QuarantineMeta{
		OriginalPath: path,
		Owner:        uid,
		Group:        gid,
		Mode:         info.Mode().String(),
		Size:         info.Size(),
		QuarantineAt: time.Now(),
		Reason:       "Inline quarantine: high-confidence realtime signature match",
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	_ = os.WriteFile(qPath+".meta", metaData, 0600)

	return qPath, true
}

// extractCategory parses "Category: <value>" from a finding's Details field.
func extractCategory(details string) string {
	for _, line := range strings.Split(details, "\n") {
		if strings.HasPrefix(line, "Category: ") {
			return strings.TrimPrefix(line, "Category: ")
		}
	}
	return ""
}
