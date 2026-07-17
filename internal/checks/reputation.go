package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/threatintel"
)

const (
	reputationCacheFile      = "reputation_cache.json"
	reputationEximMainlog    = "/var/log/exim_mainlog"
	reputationWHMAccessLog   = "/usr/local/cpanel/logs/access_log"
	cacheExpiry              = 6 * time.Hour
	errorCacheExpiry         = 1 * time.Hour // cache transient API errors to avoid retrying same IP
	abuseConfidenceThreshold = 50
	maxQueriesPerCycle       = 5    // max AbuseIPDB API calls per 10-min cycle (~720/day, fits free tier)
	maxCacheEntries          = 5000 // cap cache size
)

// maxDailyAbuseQueries is the store-backed daily circuit-breaker below
// the 1000/day free-tier ceiling. The 100-slot cushion below 1000 leaves
// room for API-side accounting differences and fallback paths that cannot
// share the store counter. Declared as a var (not const) so tests can lower it
// without burning seconds on 900 bbolt transactions. Production callers
// must not modify this.
var maxDailyAbuseQueries = 900

// abuseIPDBEndpoint is the URL queried for IP reputation. Declared as a
// var (not const) so tests can point it at an httptest server. Production
// callers must not modify this.
var abuseIPDBEndpoint = "https://api.abuseipdb.com/api/v2/check"

// abuseIPDBClient is the HTTP client used for AbuseIPDB queries. Declared
// at package scope so tests can swap in a mock client (e.g., one whose
// transport routes all traffic to an httptest server).
var abuseIPDBClient = &http.Client{Timeout: 10 * time.Second}

type reputationCache struct {
	Entries map[string]*reputationEntry `json:"entries"`

	// dirty tracks entries touched since load. nil means the cache was
	// assembled directly rather than hydrated by loadReputationCache, in
	// which case a save persists every entry.
	dirty map[string]bool

	// removed tracks evictions since load so bbolt saves can delete entries
	// pruned from the in-memory view.
	removed map[string]bool
}

type reputationEntry struct {
	Score     int       `json:"score"`
	Category  string    `json:"category"`
	CheckedAt time.Time `json:"checked_at"`
}

// set records an entry and marks it changed so a bbolt-backed save can
// persist just this cycle's writes instead of the whole map.
func (c *reputationCache) set(ip string, e *reputationEntry) {
	c.Entries[ip] = e
	if c.dirty != nil {
		c.dirty[ip] = true
		delete(c.removed, ip)
	}
}

// remove evicts an entry. Deleting any pending dirty mark keeps a later
// save from writing what eviction just removed; recording the removal lets
// bbolt delete a prior stored value for the same IP.
func (c *reputationCache) remove(ip string) {
	delete(c.Entries, ip)
	if c.dirty != nil {
		delete(c.dirty, ip)
		if c.removed != nil {
			c.removed[ip] = true
		}
	}
}

// changedEntries returns what a bbolt-backed save must persist. Without
// change tracking every entry counts as changed. With tracking, only
// entries touched since load and still present are returned: re-putting
// the full map here used to resurrect every entry the TTL/cap prune had
// just deleted, so the bucket grew without bound.
func (c *reputationCache) changedEntries() map[string]store.ReputationEntry {
	out := make(map[string]store.ReputationEntry)
	if c.dirty == nil {
		for ip, e := range c.Entries {
			out[ip] = store.ReputationEntry{Score: e.Score, Category: e.Category, CheckedAt: e.CheckedAt}
		}
		return out
	}
	for ip := range c.dirty {
		e, ok := c.Entries[ip]
		if !ok {
			continue
		}
		out[ip] = store.ReputationEntry{Score: e.Score, Category: e.Category, CheckedAt: e.CheckedAt}
	}
	return out
}

// CheckIPReputation looks up non-infra IPs against threat intelligence.
// Four-tier approach:
//  1. Skip if already blocked
//  2. Check local threat DB (permanent blocklist + free feeds)
//  3. Check AbuseIPDB cache
//  4. Query AbuseIPDB for truly unknown IPs (max 5/cycle, ~720/day)
func CheckIPReputation(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	supplementalAgg := newSupplementalThreatAggregator(cfg)
	ips := collectRecentIPs(cfg)
	if len(ips) == 0 {
		return nil
	}

	authenticated := collectAuthenticatedIPs(cfg)
	alreadyBlocked := loadAllBlockedIPs(cfg.StatePath)
	threatDB := GetThreatDB()
	cache := loadReputationCache(cfg.StatePath)
	client := abuseIPDBClient
	sdb := store.Global()
	now := time.Now()
	utcDay := now.UTC().Format("2006-01-02")
	quotaExhausted := !abuseQuotaReady(sdb, now)

	// Two-pass design so the slow AbuseIPDB HTTP queries can run in
	// parallel:
	//
	//   Pass 1 (serial): walk every IP and resolve via tier 1/2/3 plus
	//   the supplemental aggregator. Collect the IPs that genuinely
	//   need a tier-4 HTTP lookup into pendingQueries.
	//
	//   Pass 2 (parallel, up to maxQueriesPerCycle workers): fan out
	//   queryAbuseIPDB and collect results.
	//
	//   Pass 3 (serial): apply results back into the cache and emit
	//   findings.
	//
	// Pre-cache, all five HTTP queries ran in a serial loop, so a
	// cycle paid ~5x worst-case AbuseIPDB latency. A busy production
	// host saw ip_reputation averaging ~3.6 s per run because of
	// this; the fan-out brings that down to ~max(single-call latency).
	type pendingQuery struct {
		ip     string
		source string
	}
	var pendingQueries []pendingQuery

	for ip, source := range ips {
		// A source that authenticated successfully holds valid credentials and is
		// a real customer on a recycled dynamic/CGNAT address, not a drive-by
		// scanner. Reputation auto-block keys on mere passive access, so without
		// this skip a legitimate customer whose ISP-recycled IP appears in a
		// public feed gets a 24h block the instant they open webmail. Genuine
		// attacks from the same IP are still caught by the brute-force,
		// compromise, and takeover detectors, which do not honour this exemption.
		if authenticated[ip] {
			continue
		}

		// Tier 1: Skip if already blocked
		if alreadyBlocked[ip] {
			continue
		}

		// Tier 2: Check local threat DB
		if threatDB != nil {
			if dbSource, found := threatDB.Lookup(ip); found {
				findings = append(findings, alert.Finding{
					Severity:  reputationSightingSeverity(source),
					Check:     "ip_reputation",
					Message:   fmt.Sprintf("Known malicious IP accessing server: %s (source: %s)", ip, dbSource),
					Details:   fmt.Sprintf("Detected via: %s\nMatched in local threat intelligence database", source),
					Timestamp: time.Now(),
					SourceIP:  ip,
				})
				continue
			}
		}

		// Tier 3: Check AbuseIPDB cache. Treat entries with CheckedAt in
		// the future (legacy data written by a prior buggy error-caching
		// formula) as expired so they get re-queried or aged out.
		if entry, ok := cache.Entries[ip]; ok {
			age := time.Since(entry.CheckedAt)
			if age >= 0 && age < cacheExpiry {
				if entry.Score >= abuseConfidenceThreshold {
					appendReputationFinding(&findings, ip, source, "AbuseIPDB", entry.Score, entry.Category)
				} else if score, src, ok := supplementalThreatScore(ctx, supplementalAgg, ip); ok && score >= abuseConfidenceThreshold {
					appendReputationFinding(&findings, ip, source, src, score, strings.ToLower(src)+" history")
				}
				continue
			}
		}

		// Tier 4 candidate; defer the HTTP call to pass 2 unless the
		// quota / config gates already preclude querying.
		if cfg.Reputation.AbuseIPDBKey == "" || quotaExhausted || len(pendingQueries) >= maxQueriesPerCycle {
			if score, src, ok := supplementalThreatScore(ctx, supplementalAgg, ip); ok && score >= abuseConfidenceThreshold {
				appendReputationFinding(&findings, ip, source, src, score, strings.ToLower(src)+" history")
			}
			continue
		}

		pendingQueries = append(pendingQueries, pendingQuery{ip: ip, source: source})
	}

	// Pass 2: reserve daily quota slots up front and fan out the HTTP
	// calls. The pre-reservation matches the prior "count the attempt
	// before the call so a crash or network hang still consumes a slot"
	// guarantee, while keeping near-cap cycles from spending more slots
	// than the store can reserve.
	type queryResult struct {
		score    int
		category string
		err      error
	}
	if len(pendingQueries) > 0 {
		if sdb != nil {
			reserved := sdb.ReserveAbuseQuerySlots(utcDay, len(pendingQueries), maxDailyAbuseQueries)
			if reserved < len(pendingQueries) {
				for _, q := range pendingQueries[reserved:] {
					if supplemental, src, ok := supplementalThreatScore(ctx, supplementalAgg, q.ip); ok && supplemental >= abuseConfidenceThreshold {
						appendReputationFinding(&findings, q.ip, q.source, src, supplemental, strings.ToLower(src)+" history")
					}
				}
				pendingQueries = pendingQueries[:reserved]
			}
		}
	}

	results := make(map[string]queryResult, len(pendingQueries))
	if len(pendingQueries) > 0 {
		var mu sync.Mutex
		var wg sync.WaitGroup
		workers := len(pendingQueries)
		if workers > maxQueriesPerCycle {
			workers = maxQueriesPerCycle
		}
		jobs := make(chan pendingQuery, len(pendingQueries))
		for _, q := range pendingQueries {
			jobs <- q
		}
		close(jobs)
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for q := range jobs {
					score, category, err := queryAbuseIPDB(client, q.ip, cfg.Reputation.AbuseIPDBKey)
					mu.Lock()
					results[q.ip] = queryResult{score: score, category: category, err: err}
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
	}

	// Pass 3: apply each tier-4 result back into cache + findings.
	// Serial so cache writes and quota-exhaustion handling stay
	// consistent regardless of which worker observed which HTTP error.
	for _, q := range pendingQueries {
		res, ok := results[q.ip]
		if !ok {
			continue
		}
		if res.err != nil {
			if strings.Contains(res.err.Error(), "429") || strings.Contains(res.err.Error(), "402") {
				resetAt := nextUTCMidnight(time.Now())
				fmt.Fprintf(os.Stderr, "abuseipdb: quota exhausted (%v), pausing lookups until %s\n",
					res.err, resetAt.Format(time.RFC3339))
				// Persisted backoff is the load-bearing signal for the
				// next cycle's classifier; the cycle-local quotaExhausted
				// flag has no further reader past this loop.
				if sdb != nil {
					_ = sdb.SetAbuseQuotaExhaustedUntil(resetAt)
				}
				if supplemental, src, ok := supplementalThreatScore(ctx, supplementalAgg, q.ip); ok && supplemental >= abuseConfidenceThreshold {
					appendReputationFinding(&findings, q.ip, q.source, src, supplemental, strings.ToLower(src)+" history")
				}
				continue
			}
			cache.set(q.ip, &reputationEntry{
				Score:    -1,
				Category: fmt.Sprintf("error: %v", res.err),
				// CheckedAt is shifted into the past so time.Since returns
				// ~(cacheExpiry-errorCacheExpiry) immediately; the Tier-3
				// freshness check then flips false after a further
				// errorCacheExpiry, giving a real ~1h TTL on error entries.
				CheckedAt: time.Now().Add(-(cacheExpiry - errorCacheExpiry)),
			})
			if supplemental, src, ok := supplementalThreatScore(ctx, supplementalAgg, q.ip); ok && supplemental >= abuseConfidenceThreshold {
				appendReputationFinding(&findings, q.ip, q.source, src, supplemental, strings.ToLower(src)+" history")
			}
			continue
		}

		cache.set(q.ip, &reputationEntry{
			Score:     res.score,
			Category:  res.category,
			CheckedAt: time.Now(),
		})

		score := res.score
		category := res.category
		provider := "AbuseIPDB"
		if supplemental, src, ok := supplementalThreatScore(ctx, supplementalAgg, q.ip); ok && supplemental > score {
			score = supplemental
			category = strings.ToLower(src) + " history"
			provider = src
		}

		if score >= abuseConfidenceThreshold {
			appendReputationFinding(&findings, q.ip, q.source, provider, score, category)
		}
	}

	// Clean and cap cache
	cleanCache(cache)
	saveReputationCache(cfg.StatePath, cache)

	return findings
}

func newSupplementalThreatAggregator(cfg *config.Config) *threatintel.Aggregator {
	if !cfg.Reputation.Upstream.Enabled {
		threatintel.ClearUpstreamMetricsSource()
	}
	if !cfg.Reputation.Rspamd.Enabled && !cfg.Reputation.Upstream.Enabled {
		return nil
	}
	agg := threatintel.NewAggregator()
	if cfg.Reputation.Rspamd.Enabled {
		agg.Register(threatintel.NewRspamdSource(
			cfg.Reputation.Rspamd.URL,
			cfg.Reputation.Rspamd.Token,
			cfg.Reputation.Rspamd.TokenEnv,
		))
	}
	if cfg.Reputation.Upstream.Enabled {
		upstream := threatintel.NewUpstreamSource(threatintel.UpstreamConfig{
			URL:      cfg.Reputation.Upstream.URL,
			Token:    cfg.Reputation.Upstream.Token,
			TokenEnv: cfg.Reputation.Upstream.TokenEnv,
			CacheTTL: time.Duration(cfg.Reputation.Upstream.CacheTTLMin) * time.Minute,
			Timeout:  time.Duration(cfg.Reputation.Upstream.TimeoutSec) * time.Second,
		})
		threatintel.RegisterUpstreamMetrics(metrics.Default(), upstream)
		agg.Register(upstream)
	}
	return agg
}

// supplementalThreatScore queries the aggregator for ip and returns the
// aggregated score, the name of the highest-scoring individual source
// (capitalised for operator-facing messages), and whether a usable score
// was found. Returns ("", 0, false) when agg is nil or no source scored.
func supplementalThreatScore(ctx context.Context, agg *threatintel.Aggregator, ip string) (int, string, bool) {
	if agg == nil {
		return 0, "", false
	}
	res, err := agg.Score(ctx, ip)
	if err != nil || res.AggregatedScore == 0 {
		return 0, "", false
	}
	// Identify the source with the highest individual score so callers can
	// label findings accurately (e.g. "Rspamd" vs "Upstream").
	dominant := "supplemental"
	max := 0
	for name, s := range res.Sources {
		if s > max {
			max = s
			dominant = name
		}
	}
	return res.AggregatedScore, capitalizeProvider(dominant), true
}

// capitalizeProvider title-cases known source names for operator-facing
// messages ("rspamd" -> "Rspamd", "upstream" -> "Upstream").
func capitalizeProvider(name string) string {
	if len(name) == 0 {
		return name
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

// reputationSightingSeverity grades a threat-intel sighting by what the IP
// was doing. Auth-surface contact (SSH, mail credential attacks) is an
// active threat and stays Critical; a passive web sighting of a listed IP
// is ambient scanner noise, downgraded to High so thousands of drive-by
// scanners do not drown compromise-class Criticals. Auto-block eligibility
// is keyed on the check name and is not affected by this severity. Unknown
// future surfaces fail closed to Critical.
func reputationSightingSeverity(detectedVia string) alert.Severity {
	switch detectedVia {
	case "HTTP request", "cPanel/WHM access":
		return alert.High
	default:
		return alert.Critical
	}
}

func appendReputationFinding(findings *[]alert.Finding, ip, detectedVia, provider string, score int, category string) {
	*findings = append(*findings, alert.Finding{
		Severity:  reputationSightingSeverity(detectedVia),
		Check:     "ip_reputation",
		Message:   fmt.Sprintf("Known malicious IP accessing server: %s (%s score: %d/100)", ip, provider, score),
		Details:   fmt.Sprintf("Detected via: %s\nCategory: %s\nThis IP is reported in threat intelligence databases", detectedVia, category),
		Timestamp: time.Now(),
		SourceIP:  ip,
	})
}

// nextUTCMidnight returns 00:00 UTC on the day after now — the point at
// which AbuseIPDB's daily quota resets.
func nextUTCMidnight(now time.Time) time.Time {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), u.Day()+1, 0, 0, 0, 0, time.UTC)
}

// abuseQuotaReady reports whether we may call AbuseIPDB right now. It
// combines the persisted backoff (set when the API returns 429/402) with
// the daily query counter (stops before we approach the free-tier cap).
// Returns true when no bbolt store is available (fallback mode).
func abuseQuotaReady(sdb *store.DB, now time.Time) bool {
	if sdb == nil {
		return true
	}
	if until := sdb.AbuseQuotaExhaustedUntil(); !until.IsZero() && now.Before(until) {
		return false
	}
	if sdb.AbuseQueryCount(now.UTC().Format("2006-01-02")) >= maxDailyAbuseQueries {
		return false
	}
	return true
}

// collectRecentIPs gathers non-infra IPs from multiple log sources.
// Returns map of IP → source description (e.g. "SSH login", "Dovecot IMAP auth failure").
func collectRecentIPs(cfg *config.Config) map[string]string {
	ips := make(map[string]string)
	info := platform.Detect()

	// SSH logins. Path differs by OS family (secure vs auth.log); the old
	// hardcoded /var/log/secure made this loop dead on Debian/Ubuntu.
	for _, line := range tailFile(info.AuthLogPath(), 50) {
		if !strings.Contains(line, "Accepted") {
			continue
		}
		if ip := extractIPAfterKeyword(line, "from"); ip != "" {
			addIfNotInfra(ips, ip, "SSH login", cfg)
		}
	}

	// Web server access logs, platform-detected (Apache/Nginx/LiteSpeed).
	for _, path := range info.AccessLogPaths {
		if path == "" || isWHMAccessLog(path) {
			continue
		}
		lines := tailFile(path, 100)
		if len(lines) == 0 {
			continue
		}
		for _, line := range lines {
			if ip := firstField(line); ip != "" {
				addIfNotInfra(ips, ip, "HTTP request", cfg)
			}
		}
	}

	// Dovecot - IMAP/POP3 auth failures.
	if mailLog := reputationMailLogPath(cfg, info); mailLog != "" {
		for _, line := range tailFile(mailLog, 50) {
			if strings.Contains(line, "auth failed") || strings.Contains(line, "Aborted login") {
				if ip := extractIPAfterKeyword(line, "rip="); ip != "" {
					addIfNotInfra(ips, ip, "Dovecot IMAP/POP3 auth failure", cfg)
				}
			}
		}
	}

	if info.IsCPanel() {
		// cPanel/WHM access log.
		for _, line := range tailFile(reputationWHMAccessLog, 100) {
			if ip := firstField(line); ip != "" {
				addIfNotInfra(ips, ip, "cPanel/WHM access", cfg)
			}
		}
	}

	if shouldCollectEximMainlog(info) {
		for _, line := range tailFile(reputationEximMainlog, 50) {
			if strings.Contains(line, "authenticator failed") || strings.Contains(line, "rejected RCPT") {
				if ip := extractBracketedIP(line); ip != "" {
					addIfNotInfra(ips, ip, "SMTP auth failure", cfg)
				}
			}
		}
	}

	return ips
}

// collectAuthenticatedIPs returns IPs that successfully authenticated to a
// mailbox in the recent log window. A source that holds valid mail credentials
// is a real customer, not a drive-by scanner: a threat-feed match on such an IP
// is almost always a recycled dynamic/CGNAT address rather than the attacker the
// feed once listed. Romanian and other residential ISPs rotate these pools
// aggressively, so an IP an attacker used last week routinely lands on a paying
// customer this week. Webmail authenticates through dovecot, so this also covers
// Horde/Roundcube users.
//
// Successful SSH logins are deliberately excluded: a clean SSH auth from a
// feed-listed IP is itself a red flag (a cracked or attacker-controlled host),
// and collectRecentIPs already surfaces those IPs precisely so their reputation
// is checked. Authenticated mail attackers (compromised accounts) remain covered
// by the brute-force, compromise, and account-takeover detectors, which do not
// honour this exemption. The mail window is wider than collectRecentIPs uses so
// a customer's success is not pushed out of view by a burst of attacker failures
// occupying the tail.
func collectAuthenticatedIPs(cfg *config.Config) map[string]bool {
	authed := make(map[string]bool)
	info := platform.Detect()

	mailLog := reputationMailLogPath(cfg, info)
	if mailLog == "" {
		return authed
	}
	for _, line := range tailFile(mailLog, 200) {
		if !strings.Contains(line, "-login: Logged in") {
			continue
		}
		if ip := extractIPAfterKeyword(line, "rip="); ip != "" {
			authed[ip] = true
		}
	}

	return authed
}

func reputationMailLogPath(cfg *config.Config, info platform.Info) string {
	if cfg == nil {
		return info.MailLogPath()
	}
	if cfg.MailLogs.Source == "journal" {
		return ""
	}
	if cfg.MailLogs.File != "" {
		return cfg.MailLogs.File
	}
	return info.MailLogPath()
}

func isWHMAccessLog(path string) bool {
	return filepath.Clean(path) == reputationWHMAccessLog
}

func shouldCollectEximMainlog(info platform.Info) bool {
	if info.IsCPanel() {
		return true
	}
	if _, err := osFS.Stat(reputationEximMainlog); err != nil {
		return !os.IsNotExist(err)
	}
	return true
}

func addIfNotInfra(ips map[string]string, ip, source string, cfg *config.Config) {
	if ip == "127.0.0.1" || ip == "::1" || ip == "" {
		return
	}
	if isInfraIP(ip, cfg.InfraIPs) {
		return
	}
	// One address can appear on several surfaces in the same scan. Keep the
	// strongest sighting so an earlier passive web request cannot hide a later
	// authentication attack and downgrade the resulting finding.
	current, exists := ips[ip]
	if !exists || reputationSightingSeverity(source) > reputationSightingSeverity(current) {
		ips[ip] = source
	}
}

func firstField(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	ip := fields[0]
	// Validate it looks like an IP (v4 or v6)
	if strings.Count(ip, ".") == 3 || strings.Contains(ip, ":") {
		return ip
	}
	return ""
}

func extractIPAfterKeyword(line, keyword string) string {
	idx := strings.Index(line, keyword)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(keyword):]
	rest = strings.TrimLeft(rest, " =")
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	ip := strings.TrimRight(fields[0], ",:;)([]")
	if strings.Count(ip, ".") == 3 || strings.Contains(ip, ":") {
		return ip
	}
	return ""
}

func extractBracketedIP(line string) string {
	// Extract IP from [1.2.3.4] format common in exim logs
	start := strings.Index(line, "[")
	if start < 0 {
		return ""
	}
	end := strings.Index(line[start:], "]")
	if end < 0 {
		return ""
	}
	ip := line[start+1 : start+end]
	if strings.Count(ip, ".") == 3 || strings.Contains(ip, ":") {
		return ip
	}
	return ""
}

// loadAllBlockedIPs returns all IPs currently blocked in CSM.
// It reads firewall state through osFS so tests can inject a filesystem,
// then merges the legacy blocked_ips.json file.
func loadAllBlockedIPs(statePath string) map[string]bool {
	blocked := make(map[string]bool)

	// Read the authoritative firewall engine state. The engine persists
	// every block to firewall/state.json; the parallel bbolt fw:blocked
	// bucket is written only at migration, so reading it would return a
	// frozen snapshot that misses live blocks.
	fwPath := filepath.Join(statePath, "firewall", "state.json")
	if fwData, err := osFS.ReadFile(fwPath); err == nil {
		var fwState struct {
			Blocked []struct {
				IP        string    `json:"ip"`
				ExpiresAt time.Time `json:"expires_at"`
			} `json:"blocked"`
		}
		if uerr := json.Unmarshal(fwData, &fwState); uerr != nil {
			fmt.Fprintf(os.Stderr, "reputation: %s is corrupt, alert suppression degraded: %v\n", fwPath, uerr)
		} else {
			now := time.Now()
			for _, entry := range fwState.Blocked {
				if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
					blocked[entry.IP] = true
				}
			}
		}
	}

	// Also read from blocked_ips.json (legacy CSM auto-block)
	type blockedEntry struct {
		IP        string    `json:"ip"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	type blockFile struct {
		IPs     []blockedEntry `json:"ips"`
		Pending []struct {
			IP string `json:"ip"`
		} `json:"pending,omitempty"`
	}

	legacyPath := filepath.Join(statePath, "blocked_ips.json")
	data, err := osFS.ReadFile(legacyPath)
	if err == nil {
		var bf blockFile
		if uerr := json.Unmarshal(data, &bf); uerr != nil {
			fmt.Fprintf(os.Stderr, "reputation: %s is corrupt, alert suppression degraded: %v\n", legacyPath, uerr)
		} else {
			now := time.Now()
			for _, entry := range bf.IPs {
				if now.Before(entry.ExpiresAt) {
					blocked[entry.IP] = true
				}
			}
			for _, entry := range bf.Pending {
				blocked[entry.IP] = true
			}
		}
	}

	return blocked
}

type abuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		UsageType            string `json:"usageType"`
		ISP                  string `json:"isp"`
		TotalReports         int    `json:"totalReports"`
	} `json:"data"`
	Errors []struct {
		Detail string `json:"detail"`
		Status int    `json:"status"`
	} `json:"errors"`
}

// queryAbuseIPDB returns (score, category, error).
// Returns specific errors for rate limiting (429) and quota exhaustion (402).
func queryAbuseIPDB(client *http.Client, ip, apiKey string) (int, string, error) {
	req, err := http.NewRequest("GET", abuseIPDBEndpoint+"?ipAddress="+ip+"&maxAgeInDays=90", nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == 429 {
		return 0, "", fmt.Errorf("429 rate limited")
	}
	if resp.StatusCode == 402 {
		return 0, "", fmt.Errorf("402 quota exceeded")
	}
	if resp.StatusCode != 200 {
		return 0, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, "", err
	}

	if len(result.Errors) > 0 {
		return 0, "", fmt.Errorf("API error: %s", result.Errors[0].Detail)
	}

	category := result.Data.UsageType
	if result.Data.ISP != "" {
		category += " (" + result.Data.ISP + ")"
	}
	if result.Data.TotalReports > 0 {
		category += fmt.Sprintf(", %d reports", result.Data.TotalReports)
	}

	return result.Data.AbuseConfidenceScore, category, nil
}

// cleanCache removes expired entries and caps at maxCacheEntries.
func cleanCache(cache *reputationCache) {
	// When using bbolt store, delegate cleanup to store methods, then
	// mirror the prune on the in-memory view: entries deleted only in
	// bbolt would linger in the map and could be pushed back by a save.
	if sdb := store.Global(); sdb != nil {
		sdb.CleanExpiredReputation(cacheExpiry)
		sdb.EnforceReputationCap(maxCacheEntries)
	}
	pruneCacheEntries(cache)
}

// pruneCacheEntries drops expired entries from the in-memory map and
// enforces the size cap, evicting oldest first.
func pruneCacheEntries(cache *reputationCache) {
	now := time.Now()

	// Remove expired entries - use same expiry as cache freshness check
	for ip, entry := range cache.Entries {
		if now.Sub(entry.CheckedAt) > cacheExpiry {
			cache.remove(ip)
		}
	}

	// Cap at max entries - remove oldest if over limit
	if len(cache.Entries) > maxCacheEntries {
		type aged struct {
			ip  string
			age time.Duration
		}
		entries := make([]aged, 0, len(cache.Entries))
		for ip, entry := range cache.Entries {
			entries = append(entries, aged{ip, now.Sub(entry.CheckedAt)})
		}
		// Sort by age descending (oldest first)
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].age > entries[j].age
		})
		// Remove oldest until under limit
		for i := 0; i < len(entries)-maxCacheEntries; i++ {
			cache.remove(entries[i].ip)
		}
	}
}

func loadReputationCache(statePath string) *reputationCache {
	cache := &reputationCache{
		Entries: make(map[string]*reputationEntry),
		dirty:   make(map[string]bool),
		removed: make(map[string]bool),
	}

	// Try bbolt store first - after migration the flat file is renamed to .bak.
	if sdb := store.Global(); sdb != nil {
		for ip, entry := range sdb.AllReputation() {
			cache.Entries[ip] = &reputationEntry{
				Score:     entry.Score,
				Category:  entry.Category,
				CheckedAt: entry.CheckedAt,
			}
		}
		return cache
	}

	// Fallback: flat-file JSON (pre-migration).
	data, err := osFS.ReadFile(filepath.Join(statePath, reputationCacheFile))
	if err == nil {
		_ = json.Unmarshal(data, cache)
		if cache.Entries == nil {
			cache.Entries = make(map[string]*reputationEntry)
		}
	}
	return cache
}

func saveReputationCache(statePath string, cache *reputationCache) {
	if sdb := store.Global(); sdb != nil {
		changed := cache.changedEntries()
		if len(changed) == 0 && len(cache.removed) == 0 {
			return
		}
		if err := sdb.ApplyReputationChanges(changed, cache.removed); err != nil {
			// Keep the pending marks so a later save can retry the flush.
			return
		}
		clear(cache.dirty)
		clear(cache.removed)
		return
	}

	// Fallback: flat-file JSON.
	data, _ := json.MarshalIndent(cache, "", "  ")
	tmpPath := filepath.Join(statePath, reputationCacheFile+".tmp")
	_ = os.WriteFile(tmpPath, data, 0600)
	_ = os.Rename(tmpPath, filepath.Join(statePath, reputationCacheFile))
}
