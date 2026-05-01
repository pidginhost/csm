package daemon

import (
	"fmt"
	"net"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Enhanced access_log handler - catches File Manager, API failures,
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

	// File Manager write operations (port 2083)
	// Only match actual write actions - not read-only calls like get_homedir.
	// Skip 401/403 responses - the server rejected the request, no write occurred.
	// Match against the request URI only (between first pair of quotes), not the
	// full line which includes the referer URL that can contain "upload" in paths.
	if strings.Contains(line, "2083") && !strings.Contains(line, "\" 401 ") && !strings.Contains(line, "\" 403 ") {
		requestURI := extractRequestURI(lineLower)
		filemanWriteActions := []string{
			"fileman/save_file", "fileman/upload_files",
			"fileman/paste", "fileman/rename", "fileman/delete",
		}
		for _, action := range filemanWriteActions {
			if strings.Contains(requestURI, action) {
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
	// Suppress 401s that are stale-session artifacts from a recent password change.
	// When a user changes their password, in-flight browser AJAX requests (notification
	// polls, etc.) will 401 against the now-invalidated session - that's expected, not
	// an attack. Real API abuse won't correlate with a recent purge for the same account.
	if strings.Contains(line, "\" 401 ") || strings.Contains(line, "\" 403 ") {
		if strings.Contains(lineLower, "json-api") || strings.Contains(lineLower, "/execute/") {
			if !purgeTracker.isPostPurge401(ip) {
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "api_auth_failure_realtime",
					Message:  fmt.Sprintf("cPanel API auth failure from %s", ip),
					Details:  truncateDaemon(line, 300),
				})
			}
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

	// WHM login attempts (port 2086/2087). CVE-2026-41940 step 1 creates the
	// preauth session via a POST to the WHM login endpoint; the CRLF
	// injection lands when cpsrvd writes that session file. Surfacing every
	// non-infra POST gives ops a brute-force/recon signal even on patched
	// hosts. Suppressed under the cPanel-login suppression flag because WHM
	// is the admin face of cPanel and shares the same noise profile.
	isWHMPort := isWHMLogVhost(line)
	if isWHMPort && !cfg.Suppressions.SuppressCpanelLogin {
		if strings.Contains(lineLower, "post /login/?login_only=1") {
			findings = append(findings, alert.Finding{
				Severity: alert.Warning,
				Check:    "whm_login_realtime",
				Message:  fmt.Sprintf("WHM login attempt from non-infra IP: %s", ip),
				Details:  truncateDaemon(line, 200),
			})
		}
	}

	// CVE-2026-41940 step 4 fingerprint: a tokenless request to a
	// token-required WHM path triggers do_token_denied(), which the watchTowr
	// PoC abuses to promote a CRLF-injected session record into the JSON
	// cache. Legitimate WHM clients always prefix /scripts*/* with the
	// /cpsessXXXXXX/ security token, so the bare prefix on a WHM port is a
	// hard signature, not a heuristic. Matches both /scripts/ and /scripts2/
	// because the do_token_denied() trigger is path-agnostic - the watchTowr
	// PoC happens to use listaccts but any token-required endpoint works.
	// Fires regardless of suppression - this is an attack IOC, not a login.
	if isWHMPort && isUnauthWHMScriptsRequest(extractRequestURI(line)) {
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "whm_unauth_scripts_realtime",
			Message:  fmt.Sprintf("Tokenless WHM scripts request from %s (CVE-2026-41940 IOC)", ip),
			Details:  truncateDaemon(line, 300),
		})
	}

	return findings
}

// isWHMLogVhost reports whether the access-log line was served by WHM (port
// 2086 plain or 2087 SSL). cPanel's combined log format ends every line with
// the served vhost as the final double-quoted field (e.g. "host:2087"); we
// anchor on the suffix of that field to avoid matching a port-like substring
// inside a referer URL or user-agent.
func isWHMLogVhost(line string) bool {
	vhost := lastQuotedField(line)
	return strings.HasSuffix(vhost, ":2087") || strings.HasSuffix(vhost, ":2086")
}

// lastQuotedField returns the content of the final double-quoted field on the
// line, or "" if there isn't a closed pair. cPanel's log writer always emits
// the served vhost as that final field.
func lastQuotedField(line string) string {
	end := strings.LastIndex(line, "\"")
	if end <= 0 {
		return ""
	}
	start := strings.LastIndex(line[:end], "\"")
	if start < 0 {
		return ""
	}
	return line[start+1 : end]
}

// isUnauthWHMScriptsRequest returns true when the request URI targets a path
// under /scripts/ or /scripts2/ without a /cpsessXXXXXX/ security-token
// prefix - the literal step-4 fingerprint of CVE-2026-41940. Query strings
// are stripped before comparison.
func isUnauthWHMScriptsRequest(requestURI string) bool {
	parts := strings.SplitN(requestURI, " ", 3)
	if len(parts) < 2 {
		return false
	}
	path := parts[1]
	if q := strings.Index(path, "?"); q >= 0 {
		path = path[:q]
	}
	if strings.Contains(path, "/cpsess") {
		return false
	}
	return strings.HasPrefix(path, "/scripts/") || strings.HasPrefix(path, "/scripts2/")
}

// parseFTPLogLine handles FTP log entries from /var/log/messages.
func parseFTPLogLine(line string, cfg *config.Config) []alert.Finding {
	var findings []alert.Finding

	if !strings.Contains(line, "pure-ftpd") {
		return nil
	}

	// Extract the client address. Pure-ftpd's standard syslog format
	// prefixes the client as (user@addr), where addr is either an IP
	// (DontResolve=yes) or a reverse-resolved hostname (cPanel's
	// default with DontResolve=no). We try the pure-ftpd prefix first
	// and fall back to the generic "whitespace field starting with a
	// digit" scanner. If the pure-ftpd prefix contains a hostname
	// rather than an IP, no finding is emitted — we can't hold an
	// attacker accountable by hostname, and reverse-DNS lookups in the
	// log hot path are not acceptable.
	ip := extractPureFTPDClientIP(line)
	if ip == "" {
		ip = extractIPFromLogDaemon(line)
	}
	if ip == "" || isInfraIPDaemon(ip, cfg.InfraIPs) {
		return nil
	}

	// Failed authentication
	if strings.Contains(line, "Authentication failed") || strings.Contains(line, "auth failed") {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "ftp_auth_failure_realtime",
			Message:  fmt.Sprintf("FTP authentication failed from %s", ip),
			Details:  truncateDaemon(line, 200),
		})
	}

	// Successful login from non-infra
	if strings.Contains(line, "is now logged in") {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "ftp_login_realtime",
			Message:  fmt.Sprintf("FTP login from non-infra IP: %s", ip),
			Details:  truncateDaemon(line, 200),
		})
	}

	return findings
}

// extractPureFTPDClientIP parses the "(user@addr)" prefix that pure-ftpd
// prepends to every log message and returns `addr` only if it parses as
// an IP. Returns empty if the log line contains no prefix at all, the
// prefix is malformed, or addr is a reverse-resolved hostname (in which
// case the caller should not emit a finding since we can't block a
// hostname at the firewall).
func extractPureFTPDClientIP(line string) string {
	open := strings.Index(line, "(")
	if open < 0 {
		return ""
	}
	rest := line[open+1:]
	close := strings.Index(rest, ")")
	if close < 0 {
		return ""
	}
	inner := rest[:close]
	at := strings.IndexByte(inner, '@')
	if at < 0 {
		return ""
	}
	addr := inner[at+1:]
	if net.ParseIP(addr) == nil {
		return "" // hostname, not an IP — nothing we can block
	}
	return addr
}

// extractRequestURI extracts the request URI from an access log line.
// Format: ... "METHOD /path HTTP/1.1" ... → returns "/path"
// Returns the content between the first pair of quotes (the request line).
func extractRequestURI(line string) string {
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

func extractIPFromLogDaemon(line string) string {
	fields := strings.Fields(line)
	for _, f := range fields {
		if len(f) >= 7 && f[0] >= '0' && f[0] <= '9' && strings.Count(f, ".") == 3 {
			return strings.TrimRight(f, ",:;)([]")
		}
	}
	return ""
}
