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
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/threatintel"
)

const (
	reputationCacheFile      = "reputation_cache.json"
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
}

type reputationEntry struct {
	Score     int       `json:"score"`
	Category  string    `json:"category"`
	CheckedAt time.Time `json:"checked_at"`
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
		// Tier 1: Skip if already blocked
		if alreadyBlocked[ip] {
			continue
		}

		// Tier 2: Check local threat DB
		if threatDB != nil {
			if dbSource, found := threatDB.Lookup(ip); found {
				findings = append(findings, alert.Finding{
					Severity:  alert.Critical,
					Check:     "ip_reputation",
					Message:   fmt.Sprintf("Known malicious IP accessing server: %s (source: %s)", ip, dbSource),
					Details:   fmt.Sprintf("Detected via: %s\nMatched in local threat intelligence database", source),
					Timestamp: time.Now(),
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
			cache.Entries[q.ip] = &reputationEntry{
				Score:    -1,
				Category: fmt.Sprintf("error: %v", res.err),
				// CheckedAt is shifted into the past so time.Since returns
				// ~(cacheExpiry-errorCacheExpiry) immediately; the Tier-3
				// freshness check then flips false after a further
				// errorCacheExpiry, giving a real ~1h TTL on error entries.
				CheckedAt: time.Now().Add(-(cacheExpiry - errorCacheExpiry)),
			}
			if supplemental, src, ok := supplementalThreatScore(ctx, supplementalAgg, q.ip); ok && supplemental >= abuseConfidenceThreshold {
				appendReputationFinding(&findings, q.ip, q.source, src, supplemental, strings.ToLower(src)+" history")
			}
			continue
		}

		cache.Entries[q.ip] = &reputationEntry{
			Score:     res.score,
			Category:  res.category,
			CheckedAt: time.Now(),
		}

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

func appendReputationFinding(findings *[]alert.Finding, ip, detectedVia, provider string, score int, category string) {
	*findings = append(*findings, alert.Finding{
		Severity:  alert.Critical,
		Check:     "ip_reputation",
		Message:   fmt.Sprintf("Known malicious IP accessing server: %s (%s score: %d/100)", ip, provider, score),
		Details:   fmt.Sprintf("Detected via: %s\nCategory: %s\nThis IP is reported in threat intelligence databases", detectedVia, category),
		Timestamp: time.Now(),
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

	// SSH logins
	for _, line := range tailFile("/var/log/secure", 50) {
		if !strings.Contains(line, "Accepted") {
			continue
		}
		if ip := extractIPAfterKeyword(line, "from"); ip != "" {
			addIfNotInfra(ips, ip, "SSH login", cfg)
		}
	}

	// cPanel access log
	for _, line := range tailFile("/usr/local/cpanel/logs/access_log", 100) {
		if ip := firstField(line); ip != "" {
			addIfNotInfra(ips, ip, "cPanel/WHM access", cfg)
		}
	}

	// Web server access log (LiteSpeed/Apache)
	webLogPaths := []string{
		"/usr/local/apache/logs/access_log",
		"/var/log/apache2/access_log",
		"/etc/apache2/logs/access_log",
	}
	for _, path := range webLogPaths {
		lines := tailFile(path, 100)
		if len(lines) == 0 {
			continue
		}
		for _, line := range lines {
			if ip := firstField(line); ip != "" {
				addIfNotInfra(ips, ip, "HTTP request", cfg)
			}
		}
		break
	}

	// Exim log - SMTP auth failures
	for _, line := range tailFile("/var/log/exim_mainlog", 50) {
		if strings.Contains(line, "authenticator failed") || strings.Contains(line, "rejected RCPT") {
			if ip := extractBracketedIP(line); ip != "" {
				addIfNotInfra(ips, ip, "SMTP auth failure", cfg)
			}
		}
	}

	// Dovecot - IMAP/POP3 auth failures
	for _, line := range tailFile("/var/log/maillog", 50) {
		if strings.Contains(line, "auth failed") || strings.Contains(line, "Aborted login") {
			if ip := extractIPAfterKeyword(line, "rip="); ip != "" {
				addIfNotInfra(ips, ip, "Dovecot IMAP/POP3 auth failure", cfg)
			}
		}
	}

	return ips
}

func addIfNotInfra(ips map[string]string, ip, source string, cfg *config.Config) {
	if ip == "127.0.0.1" || ip == "::1" || ip == "" {
		return
	}
	if isInfraIP(ip, cfg.InfraIPs) {
		return
	}
	if _, exists := ips[ip]; !exists {
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
	if fwData, err := osFS.ReadFile(filepath.Join(statePath, "firewall", "state.json")); err == nil {
		var fwState struct {
			Blocked []struct {
				IP        string    `json:"ip"`
				ExpiresAt time.Time `json:"expires_at"`
			} `json:"blocked"`
		}
		if json.Unmarshal(fwData, &fwState) == nil {
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
		IPs []blockedEntry `json:"ips"`
	}

	data, err := osFS.ReadFile(filepath.Join(statePath, "blocked_ips.json"))
	if err == nil {
		var bf blockFile
		if err := json.Unmarshal(data, &bf); err == nil {
			now := time.Now()
			for _, entry := range bf.IPs {
				if now.Before(entry.ExpiresAt) {
					blocked[entry.IP] = true
				}
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
	// When using bbolt store, delegate cleanup to store methods.
	if sdb := store.Global(); sdb != nil {
		sdb.CleanExpiredReputation(cacheExpiry)
		sdb.EnforceReputationCap(maxCacheEntries)
		return
	}

	// Fallback: in-memory cache cleanup.
	now := time.Now()

	// Remove expired entries - use same expiry as cache freshness check
	for ip, entry := range cache.Entries {
		if now.Sub(entry.CheckedAt) > cacheExpiry {
			delete(cache.Entries, ip)
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
			delete(cache.Entries, entries[i].ip)
		}
	}
}

func loadReputationCache(statePath string) *reputationCache {
	cache := &reputationCache{Entries: make(map[string]*reputationEntry)}

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
		for ip, entry := range cache.Entries {
			_ = sdb.SetReputation(ip, store.ReputationEntry{
				Score:     entry.Score,
				Category:  entry.Category,
				CheckedAt: entry.CheckedAt,
			})
		}
		return
	}

	// Fallback: flat-file JSON.
	data, _ := json.MarshalIndent(cache, "", "  ")
	tmpPath := filepath.Join(statePath, reputationCacheFile+".tmp")
	_ = os.WriteFile(tmpPath, data, 0600)
	_ = os.Rename(tmpPath, filepath.Join(statePath, reputationCacheFile))
}
