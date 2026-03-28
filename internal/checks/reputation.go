package checks

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

const (
	abuseIPDBEndpoint        = "https://api.abuseipdb.com/api/v2/check"
	reputationCacheFile      = "reputation_cache.json"
	cacheExpiry              = 6 * time.Hour
	errorCacheExpiry         = 1 * time.Hour // cache transient API errors to avoid retrying same IP
	abuseConfidenceThreshold = 50
	maxQueriesPerCycle       = 5    // max AbuseIPDB API calls per 10-min cycle (~720/day, fits free tier)
	maxCacheEntries          = 5000 // cap cache size
)

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
//  1. Skip if already blocked in CSF
//  2. Check local threat DB (permanent blocklist + free feeds)
//  3. Check AbuseIPDB cache
//  4. Query AbuseIPDB for truly unknown IPs (max 5/cycle, ~720/day)
func CheckIPReputation(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	ips := collectRecentIPs(cfg)
	if len(ips) == 0 {
		return nil
	}

	alreadyBlocked := loadAllBlockedIPs(cfg.StatePath)
	threatDB := GetThreatDB()
	cache := loadReputationCache(cfg.StatePath)

	client := &http.Client{Timeout: 10 * time.Second}
	quotaExhausted := false

	checked := 0
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

		// Tier 3: Check AbuseIPDB cache
		if entry, ok := cache.Entries[ip]; ok {
			if time.Since(entry.CheckedAt) < cacheExpiry {
				if entry.Score >= abuseConfidenceThreshold {
					findings = append(findings, alert.Finding{
						Severity:  alert.Critical,
						Check:     "ip_reputation",
						Message:   fmt.Sprintf("Known malicious IP accessing server: %s (AbuseIPDB score: %d/100)", ip, entry.Score),
						Details:   fmt.Sprintf("Detected via: %s\nCategory: %s\nThis IP is reported in threat intelligence databases", source, entry.Category),
						Timestamp: time.Now(),
					})
				}
				continue
			}
		}

		// Tier 4: Query AbuseIPDB — skip if no key, quota exhausted, or limit reached
		if cfg.Reputation.AbuseIPDBKey == "" || quotaExhausted || checked >= maxQueriesPerCycle {
			continue
		}

		score, category, err := queryAbuseIPDB(client, ip, cfg.Reputation.AbuseIPDBKey)
		if err != nil {
			if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "402") {
				fmt.Fprintf(os.Stderr, "abuseipdb: quota exhausted (%v), stopping lookups for this cycle\n", err)
				quotaExhausted = true
				continue
			}
			cache.Entries[ip] = &reputationEntry{
				Score:     -1,
				Category:  fmt.Sprintf("error: %v", err),
				CheckedAt: time.Now().Add(cacheExpiry - errorCacheExpiry),
			}
			checked++
			continue
		}
		checked++

		cache.Entries[ip] = &reputationEntry{
			Score:     score,
			Category:  category,
			CheckedAt: time.Now(),
		}

		if score >= abuseConfidenceThreshold {
			findings = append(findings, alert.Finding{
				Severity:  alert.Critical,
				Check:     "ip_reputation",
				Message:   fmt.Sprintf("Known malicious IP accessing server: %s (AbuseIPDB score: %d/100)", ip, score),
				Details:   fmt.Sprintf("Detected via: %s\nCategory: %s\nThis IP is reported in threat intelligence databases", source, category),
				Timestamp: time.Now(),
			})
		}
	}

	// Clean and cap cache
	cleanCache(cache)
	saveReputationCache(cfg.StatePath, cache)

	return findings
}

// collectRecentIPs gathers non-infra IPs from multiple log sources.
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

	// Exim log — SMTP auth failures
	for _, line := range tailFile("/var/log/exim_mainlog", 50) {
		if strings.Contains(line, "authenticator failed") || strings.Contains(line, "rejected RCPT") {
			if ip := extractBracketedIP(line); ip != "" {
				addIfNotInfra(ips, ip, "SMTP auth failure", cfg)
			}
		}
	}

	// Dovecot — IMAP/POP3 auth failures
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
func loadAllBlockedIPs(statePath string) map[string]bool {
	blocked := make(map[string]bool)

	// Read from nftables firewall engine state
	if fwData, err := os.ReadFile(filepath.Join(statePath, "firewall", "state.json")); err == nil {
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

	type blockedEntry struct {
		IP        string    `json:"ip"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	type blockFile struct {
		IPs []blockedEntry `json:"ips"`
	}

	data, err := os.ReadFile(filepath.Join(statePath, "blocked_ips.json"))
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
	now := time.Now()

	// Remove expired entries — use same expiry as cache freshness check
	for ip, entry := range cache.Entries {
		if now.Sub(entry.CheckedAt) > cacheExpiry {
			delete(cache.Entries, ip)
		}
	}

	// Cap at max entries — remove oldest if over limit
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
	data, err := os.ReadFile(filepath.Join(statePath, reputationCacheFile))
	if err == nil {
		_ = json.Unmarshal(data, cache)
		if cache.Entries == nil {
			cache.Entries = make(map[string]*reputationEntry)
		}
	}
	return cache
}

func saveReputationCache(statePath string, cache *reputationCache) {
	data, _ := json.MarshalIndent(cache, "", "  ")
	tmpPath := filepath.Join(statePath, reputationCacheFile+".tmp")
	_ = os.WriteFile(tmpPath, data, 0600)
	_ = os.Rename(tmpPath, filepath.Join(statePath, reputationCacheFile))
}
