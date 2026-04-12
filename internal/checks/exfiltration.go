package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// CheckDatabaseDumps detects mysqldump/pg_dump processes running under
// non-root users - potential data exfiltration.
func CheckDatabaseDumps(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	dumpTools := []string{"mysqldump", "pg_dump", "mongodump"}

	procs, _ := osFS.Glob("/proc/[0-9]*/cmdline")
	for _, cmdPath := range procs {
		pid := filepath.Base(filepath.Dir(cmdPath))

		// Read UID
		statusData, _ := osFS.ReadFile(filepath.Join("/proc", pid, "status"))
		var uid string
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "Uid:\t") {
				fields := strings.Fields(strings.TrimPrefix(line, "Uid:\t"))
				if len(fields) > 0 {
					uid = fields[0]
				}
			}
		}
		// Skip root - root may run legitimate backups
		if uid == "0" || uid == "" {
			continue
		}

		cmdline, err := osFS.ReadFile(cmdPath)
		if err != nil {
			continue
		}
		cmdStr := strings.ReplaceAll(string(cmdline), "\x00", " ")

		for _, tool := range dumpTools {
			if strings.Contains(cmdStr, tool) {
				user := uidToUser(uid)
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "database_dump",
					Message:  fmt.Sprintf("Database dump by non-root user: %s (%s)", user, tool),
					Details:  fmt.Sprintf("PID: %s, UID: %s, cmdline: %s", pid, uid, strings.TrimSpace(cmdStr)),
				})
				break
			}
		}
	}

	return findings
}

// CheckOutboundPasteSites detects connections to known paste/exfiltration sites.
func CheckOutboundPasteSites(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Check running processes for connections to paste sites
	pasteSites := []string{
		"pastebin.com", "hastebin.com", "ghostbin.co",
		"paste.ee", "dpaste.org", "gist.githubusercontent.com",
		"raw.githubusercontent.com", "transfer.sh",
		"file.io", "0x0.st", "ix.io",
	}

	procs, _ := osFS.Glob("/proc/[0-9]*/cmdline")
	for _, cmdPath := range procs {
		pid := filepath.Base(filepath.Dir(cmdPath))

		statusData, _ := osFS.ReadFile(filepath.Join("/proc", pid, "status"))
		var uid string
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "Uid:\t") {
				fields := strings.Fields(strings.TrimPrefix(line, "Uid:\t"))
				if len(fields) > 0 {
					uid = fields[0]
				}
			}
		}
		if uid == "0" {
			continue
		}

		cmdline, err := osFS.ReadFile(cmdPath)
		if err != nil {
			continue
		}
		cmdStr := strings.ToLower(strings.ReplaceAll(string(cmdline), "\x00", " "))

		// Check if process is connecting to paste sites
		for _, site := range pasteSites {
			if strings.Contains(cmdStr, site) {
				user := uidToUser(uid)
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "exfiltration_paste_site",
					Message:  fmt.Sprintf("Process connecting to paste/exfiltration site: %s (user: %s)", site, user),
					Details:  fmt.Sprintf("PID: %s, cmdline: %s", pid, strings.TrimSpace(cmdStr)),
				})
				break
			}
		}
	}

	return findings
}
