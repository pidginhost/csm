package daemon

import (
	"fmt"
	"strings"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// Enhanced access_log handler - catches File Manager, API failures,
// webmail logins, wp-login brute force, and xmlrpc abuse.
func parseAccessLogLineEnhanced(line string, cfg *config.Config) []alert.Finding {
	var findings []alert.Finding

	rec, ok := checks.ParseCpanelAccessRecord(line)
	if !ok {
		return nil
	}
	ip := rec.IP

	if isInfraIPDaemon(ip, cfg.InfraIPs) || ip == "127.0.0.1" {
		return nil
	}

	target := strings.ToLower(rec.Target)
	rejected := rec.Status == "401" || rec.Status == "403"

	// File Manager write operations (port 2083)
	// Only match actual write actions - not read-only calls like get_homedir.
	// Skip 401/403 responses - the server rejected the request, no write occurred.
	// Match against the request target only, not the referer, which can
	// contain "upload" in paths.
	if rec.Port == "2083" && !rejected {
		filemanWriteActions := []string{
			"fileman/save_file", "fileman/upload_files",
			"fileman/paste", "fileman/rename", "fileman/delete",
		}
		for _, action := range filemanWriteActions {
			if strings.Contains(target, action) {
				findings = append(findings, alert.Finding{
					// Warning, not Critical: this fires on every File Manager
					// write by any customer, and 401/403 are already skipped
					// above, so it only reports authenticated operations. Its
					// value is correlation with other findings on the account,
					// not the single event.
					Severity: alert.Warning,
					Check:    "cpanel_file_upload_realtime",
					Message:  fmt.Sprintf("cPanel File Manager write from non-infra IP: %s", ip),
					Details:  truncateDaemon(line, 300),
					SourceIP: ip,
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
	// A failure counts as brute force against its source and can block it;
	// a trusted proxy's address stands for every visitor behind it.
	if rejected && !checks.IsTrustedProxy(ip, cfg) {
		if strings.Contains(target, "json-api") || strings.Contains(target, "/execute/") {
			if !purgeTracker.isPostPurge401(ip) {
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "api_auth_failure_realtime",
					Message:  fmt.Sprintf("cPanel API auth failure from %s", ip),
					Details:  truncateDaemon(line, 300),
					SourceIP: ip,
					// cpsrvd logs the connecting peer first.
					Attribution: admission.AttributionPeer,
				})
			}
		}
	}

	// Webmail login attempts (port 2095/2096), as the scheduled scan counts them.
	if !cfg.Suppressions.SuppressWebmail && rec.WebmailLogin() {
		findings = append(findings, alert.Finding{
			Severity: alert.Warning,
			Check:    "webmail_login_realtime",
			Message:  fmt.Sprintf("Webmail login attempt from non-infra IP: %s", ip),
			Details:  truncateDaemon(line, 200),
			SourceIP: ip,
		})
	}

	// WHM login attempts (port 2086/2087). CVE-2026-41940 step 1 creates the
	// preauth session via a POST to the WHM login endpoint; the CRLF
	// injection lands when cpsrvd writes that session file. Surfacing every
	// non-infra POST gives ops a brute-force/recon signal even on patched
	// hosts. Suppressed under the cPanel-login suppression flag because WHM
	// is the admin face of cPanel and shares the same noise profile.
	isWHMPort := rec.Port == "2087" || rec.Port == "2086"
	if isWHMPort && !cfg.Suppressions.SuppressCpanelLogin {
		if strings.EqualFold(rec.Method, "POST") && strings.HasPrefix(target, "/login/?login_only=1") {
			findings = append(findings, alert.Finding{
				Severity: alert.Warning,
				Check:    "whm_login_realtime",
				Message:  fmt.Sprintf("WHM login attempt from non-infra IP: %s", ip),
				Details:  truncateDaemon(line, 200),
				SourceIP: ip,
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
	if isWHMPort && isUnauthWHMScriptsTarget(rec.Target) {
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "whm_unauth_scripts_realtime",
			Message:  fmt.Sprintf("Tokenless WHM scripts request from %s (CVE-2026-41940 IOC)", ip),
			Details:  truncateDaemon(line, 300),
			SourceIP: ip,
		})
	}

	return findings
}

// isUnauthWHMScriptsTarget returns true when the request target is a path
// under /scripts/ or /scripts2/ without a /cpsessXXXXXX/ security-token
// prefix - the literal step-4 fingerprint of CVE-2026-41940. Query strings
// are stripped before comparison.
func isUnauthWHMScriptsTarget(path string) bool {
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

	ip := checks.PureFTPDClientIP(line)
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
			SourceIP: ip,
			// The pure-ftpd peer slot (checks.PureFTPDClientIP).
			Attribution: admission.AttributionPeer,
		})
	}

	// Successful login from non-infra. The scheduled ftp_logins check reads
	// the same file and will meet this line again, so the finding comes from
	// the shared builder: identical findings collapse in the state store,
	// while a login this watcher never saw is still reported by the scan.
	// The builder also drops loopback, which panel transfers use; a local
	// relay does not make the auth failure above trustworthy.
	if f, ok := checks.FTPLoginFinding(line, cfg); ok {
		findings = append(findings, f)
	}

	return findings
}
