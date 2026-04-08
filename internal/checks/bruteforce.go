package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

const (
	wpLoginThreshold = 20 // attempts per IP across all logs
	xmlrpcThreshold  = 30
	ftpFailThreshold = 10
	webmailThreshold = 10
	apiFailThreshold = 10

	// domlogTailLines is how many lines to read from each domlog.
	// 500 lines covers ~10 minutes of traffic on a busy site.
	domlogTailLines = 500

	// domlogMaxAge skips domlogs not modified recently (inactive sites).
	domlogMaxAge = 30 * time.Minute

	// domlogMaxFiles caps the number of domlogs scanned per cycle
	// to prevent unbounded I/O on servers with thousands of domains.
	domlogMaxFiles = 500
)

// CheckWPBruteForce detects brute force attacks against wp-login.php and
// xmlrpc.php by scanning access logs. Always scans per-domain domlogs
// because on LiteSpeed+cPanel, virtual host traffic only appears there.
// The central access log is scanned as a supplement.
//
// Aggregates per-IP counts across ALL domains — catches attackers who
// distribute requests across many sites to stay under per-site thresholds.
func CheckWPBruteForce(cfg *config.Config, _ *state.Store) []alert.Finding {
	window := cfg.Thresholds.BruteForceWindow
	if window <= 0 {
		window = 5000
	}

	wpLogin := make(map[string]int)
	xmlrpc := make(map[string]int)
	userEnum := make(map[string]int)

	// 1. Per-domain domlogs — primary source on LiteSpeed.
	// Glob both SSL and non-SSL logs: attackers may use HTTP.
	scanned := scanDomlogs(cfg.InfraIPs, wpLogin, xmlrpc, userEnum)

	// 2. Central access log — supplement for non-vhost traffic.
	// On LiteSpeed this mostly has WHM/server-level requests.
	// On Apache it duplicates domlog data — minor double-counting is
	// acceptable since thresholds are high enough.
	for _, p := range []string{
		"/usr/local/apache/logs/access_log",
		"/var/log/apache2/access_log",
		"/etc/apache2/logs/access_log",
	} {
		lines := tailFile(p, window)
		if len(lines) > 0 {
			countBruteForce(lines, cfg.InfraIPs, wpLogin, xmlrpc, userEnum)
			break
		}
	}

	// 3. Build findings from aggregated counters.
	var findings []alert.Finding

	for ip, count := range wpLogin {
		if count >= wpLoginThreshold {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "wp_login_bruteforce",
				Message:  fmt.Sprintf("WordPress login brute force from %s: %d attempts", ip, count),
				Details:  fmt.Sprintf("Aggregated across %d domlog files", scanned),
			})
		}
	}

	for ip, count := range xmlrpc {
		if count >= xmlrpcThreshold {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "xmlrpc_abuse",
				Message:  fmt.Sprintf("XML-RPC abuse from %s: %d requests", ip, count),
				Details:  fmt.Sprintf("Aggregated across %d domlog files", scanned),
			})
		}
	}

	for ip, count := range userEnum {
		if count >= 5 {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "wp_user_enumeration",
				Message:  fmt.Sprintf("WordPress user enumeration from %s: %d requests", ip, count),
				Details:  "Requests to /wp-json/wp/v2/users or ?author=",
			})
		}
	}

	return findings
}

// scanDomlogs globs per-domain access logs, deduplicates symlinks,
// skips stale files, and aggregates brute force counts.
// Returns the number of files actually scanned.
func scanDomlogs(infraIPs []string, wpLogin, xmlrpc, userEnum map[string]int) int {
	var domlogs []string
	for _, pattern := range []string{
		"/home/*/access-logs/*-ssl_log",
		"/home/*/access-logs/*_log",
	} {
		matches, _ := filepath.Glob(pattern)
		domlogs = append(domlogs, matches...)
	}

	// Deduplicate via resolved symlinks and skip stale logs.
	seen := make(map[string]bool)
	cutoff := time.Now().Add(-domlogMaxAge)
	scanned := 0

	for _, dl := range domlogs {
		if scanned >= domlogMaxFiles {
			break
		}

		// Resolve symlinks — cPanel often symlinks SSL and non-SSL logs.
		real, err := filepath.EvalSymlinks(dl)
		if err != nil {
			continue
		}
		if seen[real] {
			continue
		}
		seen[real] = true

		// Skip logs not modified recently — inactive sites add no value.
		info, err := os.Stat(real)
		if err != nil || info.ModTime().Before(cutoff) {
			continue
		}

		lines := tailFile(real, domlogTailLines)
		countBruteForce(lines, infraIPs, wpLogin, xmlrpc, userEnum)
		scanned++
	}

	return scanned
}

// countBruteForce parses Combined Log Format lines and increments per-IP
// counters for wp-login.php, xmlrpc.php, and user enumeration attacks.
func countBruteForce(lines []string, infraIPs []string, wpLogin, xmlrpc, userEnum map[string]int) {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		ip := fields[0]

		// Skip localhost (wp-cron self-requests), placeholder, and infra IPs.
		if ip == "127.0.0.1" || ip == "::1" || ip == "-" {
			continue
		}
		if isInfraIP(ip, infraIPs) {
			continue
		}

		method := strings.Trim(fields[5], "\"")
		uri := fields[6]

		if method == "POST" {
			if strings.Contains(uri, "wp-login.php") {
				wpLogin[ip]++
			}
			if strings.Contains(uri, "xmlrpc.php") {
				xmlrpc[ip]++
			}
		}
		// User enumeration — only exclude /users/me (authenticated self-check).
		if strings.Contains(uri, "?author=") {
			userEnum[ip]++
		} else if strings.Contains(uri, "/wp-json/wp/v2/users") &&
			!strings.Contains(uri, "/users/me") {
			userEnum[ip]++
		}
	}
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
