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
			if r.CreatedByAPI() {
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
		rec, ok := ParseCpanelAccessRecord(line)
		// Only check cPanel (port 2083) entries. Skip rejected requests - no
		// write occurred - when the line names its status unambiguously.
		if !ok || rec.Port != "2083" || rec.Status == "401" || rec.Status == "403" {
			continue
		}
		ip := rec.IP

		if !rec.Proxy && (isInfraIP(ip, cfg.InfraIPs) || ip == "127.0.0.1") {
			continue
		}
		source, dedup := "non-infra IP: "+ip, ""
		if rec.Proxy {
			source, dedup = "a service subdomain (client address unverified)", "proxy:"+ip
		}

		// Match the request target only: the referer can name upload pages
		// like upload-ajax.html. The user is "-" when unauthenticated.
		owner := ""
		if rec.User != "-" && rec.User != "" {
			owner = HostingAccountForUser(rec.User)
		}
		if rec.TargetContains(filemanWriteActions...) {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "cpanel_file_upload",
				Message:  fmt.Sprintf("cPanel File Manager write operation from %s", source),
				Details:  truncateString(line, 300),
				DedupKey: dedup,
				TenantID: owner,
			})
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
