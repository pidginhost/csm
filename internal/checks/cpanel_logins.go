package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

const (
	sessionLogPath          = "/usr/local/cpanel/logs/session_log"
	sessionLogTailLines     = 200
	defaultMultiIPThreshold = 3
	defaultMultiIPWindowMin = 60
)

// CheckCpanelLogins parses the cPanel session log for suspicious login activity:
// - cPanel (cpaneld) logins from non-infra IPs
// - Same account logged in from multiple distinct IPs (credential compromise indicator)
// - Password change purge events (attacker or auto-response password resets)
func CheckCpanelLogins(cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	lines := tailFile(sessionLogPath, sessionLogTailLines)
	if len(lines) == 0 {
		return nil
	}

	// Track logins per account for multi-IP correlation
	accountIPs := make(map[string]map[string]bool)
	var passwordChanges []string

	// Determine cutoff — only alert on events within the scan window
	cutoff := time.Now().Add(-time.Duration(multiIPWindowMin(cfg)) * time.Minute)

	for _, line := range lines {
		// Session log format:
		// [2026-03-25 07:19:47 +0200] info [cpaneld] 103.132.9.133 NEW user:token address=IP,...
		// [2026-03-25 07:38:18 +0200] info [security] internal PURGE user:token password_change

		// Parse timestamp
		ts := parseSessionTimestamp(line)
		if ts.IsZero() || ts.Before(cutoff) {
			continue
		}

		// Detect cPanel logins from non-infra IPs
		// Skip API/portal sessions (create_user_session) — only alert on direct form login
		if strings.Contains(line, "[cpaneld]") && strings.Contains(line, " NEW ") {
			if strings.Contains(line, "method=create_user_session") ||
				strings.Contains(line, "method=create_session") {
				continue
			}

			ip, account := parseCpanelLogin(line)
			if ip == "" || account == "" {
				continue
			}

			if isInfraIP(ip, cfg.InfraIPs) || ip == "127.0.0.1" || ip == "internal" {
				continue
			}

			// Track for multi-IP correlation
			if accountIPs[account] == nil {
				accountIPs[account] = make(map[string]bool)
			}
			accountIPs[account][ip] = true

			// Direct form login from non-infra = higher severity
			sev := alert.High
			if strings.Contains(line, "method=handle_form_login") {
				sev = alert.Critical
			}

			findings = append(findings, alert.Finding{
				Severity: sev,
				Check:    "cpanel_login",
				Message:  fmt.Sprintf("cPanel direct login from non-infra IP: %s (account: %s)", ip, account),
				Details:  truncateString(line, 300),
			})
		}

		// Detect password change purge events
		if strings.Contains(line, "PURGE") && strings.Contains(line, "password_change") {
			account := parsePurgeAccount(line)
			if account != "" {
				passwordChanges = append(passwordChanges, account)
			}
		}
	}

	// Multi-IP correlation: same account from 3+ distinct non-infra IPs
	threshold := multiIPThreshold(cfg)
	for account, ips := range accountIPs {
		if len(ips) >= threshold {
			ipList := make([]string, 0, len(ips))
			for ip := range ips {
				ipList = append(ipList, ip)
			}
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "cpanel_multi_ip_login",
				Message:  fmt.Sprintf("Account '%s' logged in from %d distinct IPs (credential compromise likely)", account, len(ips)),
				Details:  fmt.Sprintf("IPs: %s\nThreshold: %d IPs within %d minutes", strings.Join(ipList, ", "), threshold, multiIPWindowMin(cfg)),
			})
		}
	}

	// Password change events — deduplicate by account
	seen := make(map[string]bool)
	for _, account := range passwordChanges {
		if seen[account] {
			continue
		}
		seen[account] = true

		// Check if triggered by security module (Imunify auto-response) vs user action
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "cpanel_password_purge",
			Message:  fmt.Sprintf("cPanel sessions purged via password change for account: %s", account),
			Details:  "This may indicate an automated security response or attacker-initiated password change",
		})
	}

	return findings
}

// CheckCpanelFileManager parses the cPanel access log for file management
// operations from non-infra IPs (file uploads, edits via cPanel File Manager).
func CheckCpanelFileManager(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	lines := tailFile("/usr/local/cpanel/logs/access_log", 300)

	filemanActions := []string{
		"fileman/save_file_content",
		"fileman/upload_files",
		"fileman/save_file",
		"Fileman/save_file",
		"Fileman/upload",
		"/execute/Fileman/",
	}

	for _, line := range lines {
		// Only check cPanel (port 2083) entries
		if !strings.Contains(line, "2083") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		ip := fields[0]

		if isInfraIP(ip, cfg.InfraIPs) || ip == "127.0.0.1" {
			continue
		}

		lineLower := strings.ToLower(line)
		for _, action := range filemanActions {
			if strings.Contains(lineLower, strings.ToLower(action)) {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "cpanel_file_upload",
					Message:  fmt.Sprintf("cPanel File Manager write operation from non-infra IP: %s", ip),
					Details:  truncateString(line, 300),
				})
				break
			}
		}
	}

	return findings
}

// parseSessionTimestamp extracts the timestamp from a session log line.
// Format: [2026-03-25 07:19:47 +0200]
func parseSessionTimestamp(line string) time.Time {
	start := strings.Index(line, "[")
	end := strings.Index(line, "]")
	if start < 0 || end < 0 || end <= start+1 {
		return time.Time{}
	}
	tsStr := line[start+1 : end]
	// Try common cPanel session log formats
	for _, layout := range []string{
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05 +0000",
	} {
		if t, err := time.Parse(layout, tsStr); err == nil {
			return t
		}
	}
	return time.Time{}
}

// parseCpanelLogin extracts IP and account from a session NEW line.
// Format: [timestamp] info [cpaneld] 103.132.9.133 NEW user:token address=IP,...
func parseCpanelLogin(line string) (ip, account string) {
	// Find IP after [cpaneld]
	idx := strings.Index(line, "[cpaneld]")
	if idx < 0 {
		return "", ""
	}
	rest := strings.TrimSpace(line[idx+len("[cpaneld]"):])
	fields := strings.Fields(rest)
	if len(fields) < 3 {
		return "", ""
	}

	ip = fields[0]

	// Find account from "NEW user:token" or "NEW user:token address=..."
	for i, f := range fields {
		if f == "NEW" && i+1 < len(fields) {
			userToken := fields[i+1]
			parts := strings.SplitN(userToken, ":", 2)
			if len(parts) >= 1 {
				account = parts[0]
			}
			break
		}
	}

	return ip, account
}

// parsePurgeAccount extracts the account name from a PURGE password_change line.
// Format: [timestamp] info [security] internal PURGE user:token password_change
func parsePurgeAccount(line string) string {
	idx := strings.Index(line, "PURGE")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(line[idx+len("PURGE"):])
	fields := strings.Fields(rest)
	if len(fields) < 1 {
		return ""
	}
	parts := strings.SplitN(fields[0], ":", 2)
	if len(parts) >= 1 {
		return parts[0]
	}
	return ""
}

func multiIPThreshold(cfg *config.Config) int {
	if cfg.Thresholds.MultiIPLoginThreshold > 0 {
		return cfg.Thresholds.MultiIPLoginThreshold
	}
	return defaultMultiIPThreshold
}

func multiIPWindowMin(cfg *config.Config) int {
	if cfg.Thresholds.MultiIPLoginWindowMin > 0 {
		return cfg.Thresholds.MultiIPLoginWindowMin
	}
	return defaultMultiIPWindowMin
}
