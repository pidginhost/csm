package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
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
// Aggregates per-IP counts across ALL domains -- catches attackers who
// distribute requests across many sites to stay under per-site thresholds.
func CheckWPBruteForce(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	window := cfg.Thresholds.BruteForceWindow
	if window <= 0 {
		window = 5000
	}

	stats := newDomlogStats()

	// 1. Per-domain domlogs -- primary source on LiteSpeed.
	// Glob both SSL and non-SSL logs: attackers may use HTTP.
	scanned := scanDomlogsStats(ctx, cfg, stats)

	// 2. Central access log -- supplement for non-vhost traffic.
	// On LiteSpeed this mostly has WHM/server-level requests.
	// On Apache it duplicates domlog data; minor double-counting is
	// acceptable since thresholds are high enough.
	for _, p := range platform.Detect().AccessLogPaths {
		lines := tailFile(p, window)
		if len(lines) == 0 {
			continue
		}
		for _, line := range lines {
			rec, ok := parseAccessLogRecord(line)
			if !ok {
				continue
			}
			stats.scan(rec, cfg, currentBotClassifier(cfg))
		}
		break
	}

	findings := stats.emit(cfg)
	// Replace the generic legacy Details with the actual scanned-file count.
	for i := range findings {
		if findings[i].Details == "Aggregated across per-vhost access logs" {
			findings[i].Details = "Aggregated across " + itoa(scanned) + " per-vhost access logs"
		}
	}
	return findings
}

// scanDomlogsStats globs per-domain access logs, deduplicates symlinks, drops
// stale files, ranks survivors most-recent-first, then tails up to maxFiles
// of them and feeds each parsed record into stats. The mtime-desc sort + cap
// protects late-alphabet domains on hosts with thousands of vhosts.
//
// Separated from scanDomlogs so tests that rely on scanDomlogs' map-based API
// keep compiling; both functions share the same file-discovery behaviour.
func scanDomlogsStats(ctx context.Context, cfg *config.Config, stats *domlogStats) int {
	if cfg == nil {
		cfg = &config.Config{}
	}
	maxFiles := cfg.Thresholds.DomlogMaxFiles
	if maxFiles <= 0 {
		maxFiles = domlogMaxFiles
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return 0
	}

	globs := platform.Detect().DomlogGlobs
	var domlogs []string
	for _, pattern := range globs {
		if err := ctx.Err(); err != nil {
			return 0
		}
		matches, _ := osFS.Glob(pattern)
		domlogs = append(domlogs, matches...)
	}

	// Exclude central access logs -- scanned separately to avoid double-counting.
	excluded := map[string]bool{
		"/var/log/apache2/access.log":     true,
		"/var/log/apache2/access_log":     true,
		"/var/log/httpd/access.log":       true,
		"/var/log/httpd/access_log":       true,
		"/var/log/nginx/access.log":       true,
		"/usr/local/lsws/logs/access.log": true,
	}

	type domlogEntry struct {
		path  string
		mtime time.Time
	}
	var fresh []domlogEntry
	seen := make(map[string]bool)
	cutoff := time.Now().Add(-domlogMaxAge)

	for _, dl := range domlogs {
		if err := ctx.Err(); err != nil {
			return 0
		}
		real, err := filepath.EvalSymlinks(dl)
		if err != nil || seen[real] || excluded[real] {
			continue
		}
		seen[real] = true
		info, err := osFS.Stat(real)
		if err != nil || info.ModTime().Before(cutoff) {
			continue
		}
		fresh = append(fresh, domlogEntry{path: real, mtime: info.ModTime()})
	}

	if err := ctx.Err(); err != nil {
		return 0
	}

	sort.Slice(fresh, func(i, j int) bool {
		if fresh[i].mtime.Equal(fresh[j].mtime) {
			return fresh[i].path < fresh[j].path
		}
		return fresh[i].mtime.After(fresh[j].mtime)
	})
	if len(fresh) > maxFiles {
		fresh = fresh[:maxFiles]
	}

	scanned := 0
	for _, e := range fresh {
		if err := ctx.Err(); err != nil {
			break
		}
		lines := tailFile(e.path, domlogTailLines)
		for _, line := range lines {
			rec, ok := parseAccessLogRecord(line)
			if !ok {
				continue
			}
			stats.scan(rec, cfg, currentBotClassifier(cfg))
		}
		scanned++
	}
	return scanned
}

// scanDomlogs globs per-domain access logs, deduplicates symlinks, drops
// stale files, ranks survivors most-recent-first, then tails up to maxFiles
// of them. The mtime-desc sort + cap is what protects late-alphabet domains
// on hosts with thousands of vhosts: lexical glob order would otherwise
// hide brute force against domains beyond the cap.
//
// maxFiles <= 0 means "use built-in default". A cancelled ctx stops before
// expensive discovery work and before opening the next file.
func scanDomlogs(ctx context.Context, infraIPs []string, maxFiles int, wpLogin, xmlrpc, userEnum map[string]int) int {
	if maxFiles <= 0 {
		maxFiles = domlogMaxFiles
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return 0
	}

	globs := platform.Detect().DomlogGlobs
	var domlogs []string
	for _, pattern := range globs {
		if err := ctx.Err(); err != nil {
			return 0
		}
		matches, _ := osFS.Glob(pattern)
		domlogs = append(domlogs, matches...)
	}

	// Exclude central access logs -- they are scanned separately by
	// CheckWPBruteForce so counting them here would double-count traffic.
	// Go's filepath.Glob has no negation, so we filter after expansion.
	excluded := map[string]bool{
		"/var/log/apache2/access.log":     true,
		"/var/log/apache2/access_log":     true,
		"/var/log/httpd/access.log":       true,
		"/var/log/httpd/access_log":       true,
		"/var/log/nginx/access.log":       true,
		"/usr/local/lsws/logs/access.log": true,
	}

	type domlogEntry struct {
		path  string
		mtime time.Time
	}
	var fresh []domlogEntry
	seen := make(map[string]bool)
	cutoff := time.Now().Add(-domlogMaxAge)

	for _, dl := range domlogs {
		if err := ctx.Err(); err != nil {
			return 0
		}

		// Resolve symlinks first -- cPanel often symlinks SSL and non-SSL
		// logs to the same backing file, so we dedupe on the real path.
		real, err := filepath.EvalSymlinks(dl)
		if err != nil {
			continue
		}
		if seen[real] {
			continue
		}
		seen[real] = true

		if excluded[real] {
			continue
		}

		// Inactive sites add no signal; filter before the cap so they
		// cannot crowd active sites out of the budget.
		info, err := osFS.Stat(real)
		if err != nil || info.ModTime().Before(cutoff) {
			continue
		}

		fresh = append(fresh, domlogEntry{path: real, mtime: info.ModTime()})
	}

	if err := ctx.Err(); err != nil {
		return 0
	}

	// Rank by mtime desc so the cap chops the least-recently-active tail.
	sort.Slice(fresh, func(i, j int) bool {
		if fresh[i].mtime.Equal(fresh[j].mtime) {
			return fresh[i].path < fresh[j].path
		}
		return fresh[i].mtime.After(fresh[j].mtime)
	})
	if len(fresh) > maxFiles {
		fresh = fresh[:maxFiles]
	}

	scanned := 0
	for _, e := range fresh {
		if err := ctx.Err(); err != nil {
			break
		}
		lines := tailFile(e.path, domlogTailLines)
		countBruteForce(lines, infraIPs, wpLogin, xmlrpc, userEnum)
		scanned++
	}

	return scanned
}

// countBruteForce parses Combined Log Format lines and increments per-IP
// counters via the shared domlogStats aggregator. Kept as a thin
// shim so CheckWPBruteForce keeps its old structure.
func countBruteForce(lines []string, infraIPs []string, wpLogin, xmlrpc, userEnum map[string]int) {
	cfg := &config.Config{InfraIPs: infraIPs}
	stats := newDomlogStats()
	stats.wpLogin = wpLogin
	stats.xmlrpc = xmlrpc
	stats.userEnum = userEnum
	for _, line := range lines {
		rec, ok := parseAccessLogRecord(line)
		if !ok {
			continue
		}
		stats.scan(rec, cfg, nopBotClassifier{})
	}
}

// CheckFTPLogins parses /var/log/messages or pure-ftpd log for FTP brute force.
func CheckFTPLogins(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
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
func CheckWebmailLogins(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
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
func CheckAPIAuthFailures(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
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
