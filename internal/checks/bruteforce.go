package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// domlogDiscoveryDropped counts per-vhost log paths the discovery helper
// dropped silently (broken symlink, Stat failure). Same family of
// hidden-input bug as the lex-order issue scanDomlogs already fixed:
// without telemetry, operators have no way to notice when discovery
// loses a sizable fraction of the vhosts they expected to scan.
var (
	domlogDiscoveryDropped     *metrics.CounterVec
	domlogDiscoveryDroppedOnce sync.Once
)

func observeDomlogDrop(reason string) {
	domlogDiscoveryDroppedOnce.Do(func() {
		domlogDiscoveryDropped = metrics.NewCounterVec(
			"csm_checks_domlog_discovery_dropped_total",
			"Per-vhost access-log paths the WP brute-force domlog discovery helper dropped before scanning. Labels: reason (evalsymlinks_error|stat_error). Steady growth means a chunk of vhosts is being silently skipped each cycle -- usually a broken symlink farm or a permissions regression on the log directory. Stale-mtime drops are intentional filtering, not counted here.",
			[]string{"reason"},
		)
		metrics.MustRegister("csm_checks_domlog_discovery_dropped_total", domlogDiscoveryDropped)
	})
	domlogDiscoveryDropped.With(reason).Inc()
}

const (
	wpLoginThreshold = 20 // attempts per IP across all logs
	xmlrpcThreshold  = 30
	ftpFailThreshold = 10
	webmailThreshold = 10
	apiFailThreshold = 10

	// domlogTailLines is the built-in default for how many trailing lines
	// to read from each domlog. Operators can override via
	// cfg.Thresholds.DomlogTailLines. 500 covers ~10 minutes of traffic
	// on a busy site.
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

// knownCentralAccessLogPaths lists central web-server log paths that may
// appear in broad per-vhost glob patterns. CheckWPBruteForce tails these on
// its own pass, so per-vhost discovery filters them to avoid counting the
// same lines twice.
var knownCentralAccessLogPaths = []string{
	"/var/log/apache2/access.log",
	"/var/log/apache2/access_log",
	"/var/log/httpd/access.log",
	"/var/log/httpd/access_log",
	"/var/log/nginx/access.log",
	"/usr/local/lsws/logs/access.log",
}

// discoverFreshDomlogs returns per-vhost access-log paths ready to tail.
// It globs platform.DomlogGlobs, dedupes by resolved-symlink real path,
// excludes the well-known central logs (so they are not double-counted),
// drops files untouched in the last domlogMaxAge, ranks survivors
// most-recent-first, and caps the result at maxFiles.
//
// Mtime-desc + cap is the fairness invariant: lexical glob order plus a
// hard cap would systematically hide brute force on late-alphabet
// domains. maxFiles <= 0 falls back to the built-in domlogMaxFiles
// default. A canceled ctx returns nil and stops before any further work.
//
// Shared by scanDomlogs and scanDomlogsStats so the discovery semantics
// stay locked together; each caller layers its own per-line aggregator
// on top.
func discoverFreshDomlogs(ctx context.Context, maxFiles int) []string {
	if maxFiles <= 0 {
		maxFiles = domlogMaxFiles
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil
	}

	platformInfo := platform.Detect()
	globs := platformInfo.DomlogGlobs
	centralLogs := centralAccessLogSet(platformInfo.AccessLogPaths)
	var domlogs []string
	for _, pattern := range globs {
		if err := ctx.Err(); err != nil {
			return nil
		}
		matches, _ := osFS.Glob(pattern)
		domlogs = append(domlogs, matches...)
	}

	type domlogEntry struct {
		path  string
		mtime time.Time
	}
	fresh := make([]domlogEntry, 0, len(domlogs))
	seen := make(map[string]bool)
	cutoff := time.Now().Add(-domlogMaxAge)

	for _, dl := range domlogs {
		if err := ctx.Err(); err != nil {
			return nil
		}

		// Resolve symlinks first -- cPanel symlinks SSL and non-SSL
		// logs to the same backing file; dedupe on the real path.
		real, err := filepath.EvalSymlinks(dl)
		if err != nil {
			observeDomlogDrop("evalsymlinks_error")
			continue
		}
		if seen[real] || centralLogs[real] {
			continue
		}
		seen[real] = true

		// Inactive sites add no signal; filter before the cap so they
		// cannot crowd active sites out of the budget.
		info, err := osFS.Stat(real)
		if err != nil {
			observeDomlogDrop("stat_error")
			continue
		}
		if info.ModTime().Before(cutoff) {
			continue
		}

		fresh = append(fresh, domlogEntry{path: real, mtime: info.ModTime()})
	}

	if err := ctx.Err(); err != nil {
		return nil
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

	out := make([]string, len(fresh))
	for i, e := range fresh {
		out[i] = e.path
	}
	return out
}

func centralAccessLogSet(configured []string) map[string]bool {
	out := make(map[string]bool, len(knownCentralAccessLogPaths)+len(configured))
	for _, p := range knownCentralAccessLogPaths {
		addCentralAccessLog(out, p)
	}
	// Multiple AccessLogPaths are fallback candidates; CheckWPBruteForce
	// tails only the first one with data, so excluding every candidate here
	// would drop later logs that were never scanned centrally.
	if len(configured) == 1 {
		addCentralAccessLog(out, configured[0])
	}
	return out
}

func addCentralAccessLog(out map[string]bool, path string) {
	if path == "" {
		return
	}
	out[path] = true
	if real, err := filepath.EvalSymlinks(path); err == nil {
		out[real] = true
	}
}

// effectiveDomlogTailLines returns the operator-configured
// thresholds.domlog_tail_lines value or the built-in default when unset.
func effectiveDomlogTailLines(cfg *config.Config) int {
	if cfg == nil || cfg.Thresholds.DomlogTailLines <= 0 {
		return domlogTailLines
	}
	return cfg.Thresholds.DomlogTailLines
}

// scanDomlogsStats tails the discovered per-vhost logs and feeds each
// parsed record into stats. Returns the number of files actually tailed.
func scanDomlogsStats(ctx context.Context, cfg *config.Config, stats *domlogStats) int {
	if cfg == nil {
		cfg = &config.Config{}
	}
	paths := discoverFreshDomlogs(ctx, cfg.Thresholds.DomlogMaxFiles)
	classifier := currentBotClassifier(cfg)
	tailLines := effectiveDomlogTailLines(cfg)
	scanned := 0
	for _, p := range paths {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				break
			}
		}
		for _, line := range tailFile(p, tailLines) {
			rec, ok := parseAccessLogRecord(line)
			if !ok {
				continue
			}
			stats.scan(rec, cfg, classifier)
		}
		scanned++
	}
	return scanned
}

// scanDomlogs tails the discovered per-vhost logs and increments the
// caller-owned wpLogin / xmlrpc / userEnum counters via countBruteForce.
// Returns the number of files actually tailed.
//
// maxFiles <= 0 falls back to the built-in domlogMaxFiles default. Tail
// length is the built-in default; the typed wrapper scanDomlogsStats
// honours cfg.Thresholds.DomlogTailLines when called from production.
func scanDomlogs(ctx context.Context, infraIPs []string, maxFiles int, wpLogin, xmlrpc, userEnum map[string]int) int {
	paths := discoverFreshDomlogs(ctx, maxFiles)
	scanned := 0
	for _, p := range paths {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				break
			}
		}
		lines := tailFile(p, domlogTailLines)
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
