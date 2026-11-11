package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

const (
	sessionLogPath          = "/usr/local/cpanel/logs/session_log"
	sessionLogTailLines     = 1000
	defaultMultiIPThreshold = 3
	defaultMultiIPWindowMin = 60
)

// CheckCpanelLogins parses the cPanel session log for suspicious login activity:
// - cPanel (cpaneld) logins from non-infra IPs
// - Same account logged in from multiple distinct IPs (credential compromise indicator)
// - Password change purge events (attacker or auto-response password resets)
func CheckCpanelLogins(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	lines := tailFile(sessionLogPath, sessionLogTailLines)
	if len(lines) == 0 {
		return nil
	}

	// Track logins per account for multi-IP correlation
	accountIPs := make(map[string]map[string]bool)
	var passwordChanges []string

	// Determine cutoff - only alert on events within the scan window
	cutoff := time.Now().Add(-time.Duration(multiIPWindowMin(cfg)) * time.Minute)

	for _, line := range lines {
		r, ok := ParseSessionRecord(line)
		if !ok || r.At.IsZero() || r.At.Before(cutoff) {
			continue
		}

		// Detect cPanel logins from non-infra IPs
		// Skip API/portal sessions (create_user_session) - only alert on direct form login
		if r.Service == "cpaneld" && r.Event == "NEW" {
			if cfg.Suppressions.SuppressCpanelLogin {
				// Still track IPs for multi-IP correlation even when suppressed
			} else if r.CreatedByAPI() {
				continue
			}

			addr, ok := r.ClientAddr()
			if !ok || addr.IsLoopback() || isInfraIP(addr.String(), cfg.InfraIPs) {
				continue
			}
			ip, account := addr.String(), r.Account

			// Always track for multi-IP correlation (even when login alerts suppressed)
			if accountIPs[account] == nil {
				accountIPs[account] = make(map[string]bool)
			}
			accountIPs[account][ip] = true

			// WARNING severity - logins are audit trail, not paging-level.
			// Multi-IP correlation stays CRITICAL via its own check below.
			if !cfg.Suppressions.SuppressCpanelLogin {
				findings = append(findings, alert.Finding{
					Severity: alert.Warning,
					Check:    "cpanel_login",
					Message:  fmt.Sprintf("cPanel direct login from non-infra IP: %s (account: %s)", ip, account),
					Details:  truncateString(line, 300),
					SourceIP: ip,
				})
			}
		}

		// Detect password change purge events
		if r.Event == "PURGE" && r.Reason() == "password_change" {
			passwordChanges = append(passwordChanges, r.Account)
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
				TenantID: HostingAccountForUser(account),
			})
		}
	}

	// Password change events - deduplicate by account
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
func CheckCpanelFileManager(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	lines := tailFile("/usr/local/cpanel/logs/access_log", 300)

	// Only match actual write actions - not read-only calls like get_homedir.
	// Skip 401/403 responses - the server rejected the request, no write occurred.
	// Match against request URI only, not the full line (referer can contain "upload").
	filemanWriteActions := []string{
		"fileman/save_file_content",
		"fileman/upload_files",
		"fileman/save_file",
		"fileman/paste",
		"fileman/rename",
		"fileman/delete",
	}

	for _, line := range lines {
		// Only check cPanel (port 2083) entries
		if !strings.Contains(line, "2083") {
			continue
		}

		// Skip rejected requests - no write occurred
		if strings.Contains(line, "\" 401 ") || strings.Contains(line, "\" 403 ") {
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

		// Extract request URI (between first pair of quotes) to avoid
		// matching "upload" in referer URLs like upload-ajax.html
		requestURI := extractRequestURIChecks(line)
		// Common log format: the authenticated cPanel user is the third
		// field, "-" when the request was unauthenticated.
		owner := ""
		if len(fields) >= 3 && fields[2] != "-" {
			owner = HostingAccountForUser(fields[2])
		}
		for _, action := range filemanWriteActions {
			if strings.Contains(strings.ToLower(requestURI), strings.ToLower(action)) {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "cpanel_file_upload",
					Message:  fmt.Sprintf("cPanel File Manager write operation from non-infra IP: %s", ip),
					Details:  truncateString(line, 300),
					TenantID: owner,
				})
				break
			}
		}
	}

	return findings
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

// extractRequestURIChecks extracts the request line from an access log entry.
// Format: ... "METHOD /path HTTP/1.1" ... → returns "METHOD /path HTTP/1.1"
func extractRequestURIChecks(line string) string {
	start := strings.Index(line, "\"")
	if start < 0 {
		return ""
	}
	end := strings.Index(line[start+1:], "\"")
	if end < 0 {
		return ""
	}
	return line[start+1 : start+1+end]
}
