package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

const quarantineDir = "/opt/csm/quarantine"

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

		// Extract PID from details
		pid := extractPID(f.Details)
		if pid == "" {
			continue
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
		pidInt := 0
		fmt.Sscanf(pid, "%d", &pidInt)
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
		switch f.Check {
		case "webshell", "backdoor_binary", "new_webshell_file", "new_executable_in_config",
			"obfuscated_php", "php_dropper", "suspicious_php_content",
			"new_php_in_languages", "new_php_in_upgrade", "cpanel_file_upload",
			"phishing_page":
		default:
			continue
		}
		if f.Severity != alert.Critical {
			continue
		}

		// Extract file path from message
		path := extractFilePath(f.Message)
		if path == "" {
			continue
		}

		// Verify file or directory exists
		info, err := os.Stat(path)
		if err != nil {
			continue
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
				// Cleaning failed — fall through to quarantine
				actions = append(actions, alert.Finding{
					Severity:  alert.Warning,
					Check:     "auto_response",
					Message:   fmt.Sprintf("AUTO-CLEAN failed for %s, quarantining instead", path),
					Details:   result.Error,
					Timestamp: time.Now(),
				})
				// Don't continue — fall through to quarantine below
			default:
				continue // no changes needed
			}
		}

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
				data, readErr := os.ReadFile(path)
				if readErr != nil {
					continue
				}
				if writeErr := os.WriteFile(qPath, data, 0600); writeErr != nil {
					continue
				}
				os.Remove(path)
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

func extractPID(details string) string {
	// Look for "PID: 12345" pattern
	if idx := strings.Index(details, "PID: "); idx >= 0 {
		rest := details[idx+5:]
		fields := strings.SplitN(rest, ",", 2)
		return strings.TrimSpace(fields[0])
	}
	return ""
}

func extractFilePath(message string) string {
	// Look for /home/... or /tmp/... paths in the message
	for _, prefix := range []string{"/home/", "/tmp/", "/dev/shm/", "/var/tmp/"} {
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
	data, err := os.ReadFile(filepath.Join("/proc", pid, "status"))
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
	exe, err := os.Readlink(filepath.Join("/proc", pid, "exe"))
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
