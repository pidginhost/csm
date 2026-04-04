package checks

import (
	"fmt"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

const (
	wpLoginThreshold = 20 // failed attempts in log window
	xmlrpcThreshold  = 30
	ftpFailThreshold = 10
	webmailThreshold = 10
	apiFailThreshold = 10
)

// CheckWPBruteForce parses the LiteSpeed/Apache access log for brute force
// attacks against wp-login.php and xmlrpc.php.
func CheckWPBruteForce(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Check LiteSpeed access log (most common on cPanel)
	logPaths := []string{
		"/usr/local/apache/logs/access_log",
		"/var/log/apache2/access_log",
		"/etc/apache2/logs/access_log",
	}

	window := cfg.Thresholds.BruteForceWindow
	if window <= 0 {
		window = 5000
	}

	var lines []string
	for _, path := range logPaths {
		lines = tailFile(path, window)
		if len(lines) > 0 {
			break
		}
	}
	if len(lines) == 0 {
		return nil
	}

	// Count POST requests to wp-login.php and xmlrpc.php per IP
	wpLoginAttempts := make(map[string]int)
	xmlrpcAttempts := make(map[string]int)
	userEnumAttempts := make(map[string]int)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		ip := fields[0]
		method := strings.Trim(fields[5], "\"")
		path := fields[6]

		if method == "POST" && strings.Contains(path, "wp-login.php") {
			wpLoginAttempts[ip]++
		}
		if method == "POST" && strings.Contains(path, "xmlrpc.php") {
			xmlrpcAttempts[ip]++
		}
		// WordPress REST API user enumeration
		if strings.Contains(path, "/wp-json/wp/v2/users") || strings.Contains(path, "?author=") {
			userEnumAttempts[ip]++
		}
	}

	for ip, count := range wpLoginAttempts {
		if count >= wpLoginThreshold {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "wp_login_bruteforce",
				Message:  fmt.Sprintf("WordPress login brute force from %s: %d attempts", ip, count),
				Details:  "High rate of POST requests to wp-login.php",
			})
		}
	}

	for ip, count := range xmlrpcAttempts {
		if count >= xmlrpcThreshold {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "xmlrpc_abuse",
				Message:  fmt.Sprintf("XML-RPC abuse from %s: %d requests", ip, count),
				Details:  "High rate of POST requests to xmlrpc.php (brute force or amplification)",
			})
		}
	}

	for ip, count := range userEnumAttempts {
		if count >= 5 {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "wp_user_enumeration",
				Message:  fmt.Sprintf("WordPress user enumeration from %s: %d requests", ip, count),
				Details:  "Requests to /wp-json/wp/v2/users or ?author= (attacker mapping admin usernames)",
			})
		}
	}

	return findings
}

// CheckFTPLogins parses /var/log/messages or pure-ftpd log for FTP brute force.
func CheckFTPLogins(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	lines := tailFile("/var/log/messages", 200)
	if len(lines) == 0 {
		return nil
	}

	failedFTP := make(map[string]int)

	for _, line := range lines {
		// pure-ftpd logs: "pure-ftpd: ... [WARNING] Authentication failed for user"
		if !strings.Contains(line, "pure-ftpd") {
			continue
		}

		if strings.Contains(line, "Authentication failed") || strings.Contains(line, "auth failed") {
			// Extract IP
			ip := extractIPFromLog(line)
			if ip != "" && !isInfraIP(ip, cfg.InfraIPs) {
				failedFTP[ip]++
			}
		}

		// Successful FTP login from non-infra
		if strings.Contains(line, "is now logged in") {
			ip := extractIPFromLog(line)
			if ip != "" && !isInfraIP(ip, cfg.InfraIPs) {
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "ftp_login",
					Message:  fmt.Sprintf("FTP login from non-infra IP: %s", ip),
					Details:  truncate(line, 200),
				})
			}
		}
	}

	for ip, count := range failedFTP {
		if count >= ftpFailThreshold {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "ftp_bruteforce",
				Message:  fmt.Sprintf("FTP brute force from %s: %d failed attempts", ip, count),
			})
		}
	}

	return findings
}

// CheckWebmailLogins parses cPanel access log for webmail logins from non-infra IPs.
func CheckWebmailLogins(cfg *config.Config, _ *state.Store) []alert.Finding {
	if cfg.Suppressions.SuppressWebmail {
		return nil
	}

	var findings []alert.Finding

	lines := tailFile("/usr/local/cpanel/logs/access_log", 300)

	loginAttempts := make(map[string]int)

	for _, line := range lines {
		// Webmail ports: 2095 (HTTP), 2096 (HTTPS)
		if !strings.Contains(line, "2095") && !strings.Contains(line, "2096") {
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

		// Count login attempts per IP
		if strings.Contains(line, "POST") && (strings.Contains(line, "login") || strings.Contains(line, "auth")) {
			loginAttempts[ip]++
		}
	}

	for ip, count := range loginAttempts {
		if count >= webmailThreshold {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "webmail_bruteforce",
				Message:  fmt.Sprintf("Webmail brute force from %s: %d attempts", ip, count),
			})
		}
	}

	return findings
}

// CheckAPIAuthFailures parses cPanel access log for failed API authentication.
func CheckAPIAuthFailures(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	lines := tailFile("/usr/local/cpanel/logs/access_log", 300)

	failedAPI := make(map[string]int)

	for _, line := range lines {
		// Look for 401/403 responses on API endpoints
		if !strings.Contains(line, "\" 401 ") && !strings.Contains(line, "\" 403 ") {
			continue
		}

		// Only API endpoints
		if !strings.Contains(line, "json-api") && !strings.Contains(line, "/execute/") &&
			!strings.Contains(line, "cpsess") {
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

		failedAPI[ip]++
	}

	for ip, count := range failedAPI {
		if count >= apiFailThreshold {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "api_auth_failure",
				Message:  fmt.Sprintf("cPanel API auth failures from %s: %d attempts", ip, count),
				Details:  "Possible API token brute force or unauthorized API access",
			})
		}
	}

	return findings
}

// extractIPFromLog tries to extract an IP address from a log line.
func extractIPFromLog(line string) string {
	// Look for IP pattern in common positions
	fields := strings.Fields(line)
	for _, f := range fields {
		// Simple IP detection: starts with digit, contains dots
		if len(f) >= 7 && f[0] >= '0' && f[0] <= '9' && strings.Count(f, ".") == 3 {
			// Strip trailing punctuation
			f = strings.TrimRight(f, ",:;)([]")
			return f
		}
	}
	return ""
}
