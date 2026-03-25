package daemon

import (
	"fmt"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

// Enhanced access_log handler — catches File Manager, API failures,
// webmail logins, wp-login brute force, and xmlrpc abuse.
func parseAccessLogLineEnhanced(line string, cfg *config.Config) []alert.Finding {
	var findings []alert.Finding

	fields := strings.Fields(line)
	if len(fields) < 7 {
		return nil
	}
	ip := fields[0]

	if isInfraIPDaemon(ip, cfg.InfraIPs) || ip == "127.0.0.1" {
		return nil
	}

	lineLower := strings.ToLower(line)

	// File Manager operations (port 2083)
	if strings.Contains(line, "2083") {
		filemanActions := []string{
			"fileman/save_file", "fileman/upload_files",
			"fileman/save_file", "fileman/upload",
			"/execute/fileman/",
		}
		for _, action := range filemanActions {
			if strings.Contains(lineLower, action) {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "cpanel_file_upload_realtime",
					Message:  fmt.Sprintf("cPanel File Manager write from non-infra IP: %s", ip),
					Details:  truncateDaemon(line, 300),
				})
				break
			}
		}
	}

	// API authentication failures (401/403)
	if strings.Contains(line, "\" 401 ") || strings.Contains(line, "\" 403 ") {
		if strings.Contains(lineLower, "json-api") || strings.Contains(lineLower, "/execute/") {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "api_auth_failure_realtime",
				Message:  fmt.Sprintf("cPanel API auth failure from %s", ip),
				Details:  truncateDaemon(line, 300),
			})
		}
	}

	// Webmail login attempts (port 2095/2096)
	if !cfg.Suppressions.SuppressWebmail {
		if strings.Contains(line, "2095") || strings.Contains(line, "2096") {
			if strings.Contains(lineLower, "post") {
				findings = append(findings, alert.Finding{
					Severity: alert.Warning,
					Check:    "webmail_login_realtime",
					Message:  fmt.Sprintf("Webmail login attempt from non-infra IP: %s", ip),
					Details:  truncateDaemon(line, 200),
				})
			}
		}
	}

	return findings
}

// parseFTPLogLine handles FTP log entries from /var/log/messages.
func parseFTPLogLine(line string, cfg *config.Config) []alert.Finding {
	var findings []alert.Finding

	if !strings.Contains(line, "pure-ftpd") {
		return nil
	}

	// Failed authentication
	if strings.Contains(line, "Authentication failed") || strings.Contains(line, "auth failed") {
		ip := extractIPFromLogDaemon(line)
		if ip != "" && !isInfraIPDaemon(ip, cfg.InfraIPs) {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "ftp_auth_failure_realtime",
				Message:  fmt.Sprintf("FTP authentication failed from %s", ip),
				Details:  truncateDaemon(line, 200),
			})
		}
	}

	// Successful login from non-infra
	if strings.Contains(line, "is now logged in") {
		ip := extractIPFromLogDaemon(line)
		if ip != "" && !isInfraIPDaemon(ip, cfg.InfraIPs) {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "ftp_login_realtime",
				Message:  fmt.Sprintf("FTP login from non-infra IP: %s", ip),
				Details:  truncateDaemon(line, 200),
			})
		}
	}

	return findings
}

func extractIPFromLogDaemon(line string) string {
	fields := strings.Fields(line)
	for _, f := range fields {
		if len(f) >= 7 && f[0] >= '0' && f[0] <= '9' && strings.Count(f, ".") == 3 {
			return strings.TrimRight(f, ",:;)([]")
		}
	}
	return ""
}
