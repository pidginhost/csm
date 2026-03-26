package checks

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
	abuseConfidenceThreshold = 50 // AbuseIPDB confidence score 0-100
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
// Tiered approach to minimize API calls and alert noise:
//  1. Skip if IP is already blocked in CSF → no alert, no API call
//  2. Skip if IP is in local cache with bad score → block immediately, no API call
//  3. Only query AbuseIPDB for truly new IPs never seen before
func CheckIPReputation(cfg *config.Config, _ *state.Store) []alert.Finding {
	if cfg.Reputation.AbuseIPDBKey == "" {
		return nil
	}

	var findings []alert.Finding

	ips := collectRecentIPs(cfg)
	if len(ips) == 0 {
		return nil
	}

	// Load blocked IPs from CSF deny list + CSM block state
	alreadyBlocked := loadAllBlockedIPs(cfg.StatePath)

	// Load local threat database and reputation cache
	threatDB := GetThreatDB()
	cache := loadReputationCache(cfg.StatePath)

	client := &http.Client{Timeout: 10 * time.Second}

	checked := 0
	for ip := range ips {
		// Tier 1: Skip if already blocked in CSF — no alert, no API call
		if alreadyBlocked[ip] {
			continue
		}

		// Tier 2: Check local threat database (permanent blocklist + free feeds)
		if threatDB != nil {
			if source, found := threatDB.Lookup(ip); found {
				findings = append(findings, alert.Finding{
					Severity:  alert.Critical,
					Check:     "ip_reputation",
					Message:   fmt.Sprintf("Known malicious IP accessing server: %s (source: %s)", ip, source),
					Details:   "Matched in local threat intelligence database",
					Timestamp: time.Now(),
				})
				continue
			}
		}

		// Tier 3: Check AbuseIPDB cache — if known bad, alert without API call
		if entry, ok := cache.Entries[ip]; ok {
			if time.Since(entry.CheckedAt) < cacheExpiry {
				if entry.Score >= abuseConfidenceThreshold {
					findings = append(findings, alert.Finding{
						Severity:  alert.Critical,
						Check:     "ip_reputation",
						Message:   fmt.Sprintf("Known malicious IP accessing server: %s (AbuseIPDB score: %d/100)", ip, entry.Score),
						Details:   fmt.Sprintf("Category: %s\nThis IP is reported in threat intelligence databases", entry.Category),
						Timestamp: time.Now(),
					})
				}
				continue
			}
		}

		// Tier 4: Query AbuseIPDB for truly unknown IPs — max 10 per cycle
		if cfg.Reputation.AbuseIPDBKey == "" || checked >= 10 {
			continue
		}

		score, category := queryAbuseIPDB(client, ip, cfg.Reputation.AbuseIPDBKey)
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
				Details:   fmt.Sprintf("Category: %s\nThis IP is reported in threat intelligence databases", category),
				Timestamp: time.Now(),
			})
		}
	}

	// Clean old entries
	for ip, entry := range cache.Entries {
		if time.Since(entry.CheckedAt) > 24*time.Hour {
			delete(cache.Entries, ip)
		}
	}

	saveReputationCache(cfg.StatePath, cache)

	return findings
}

func collectRecentIPs(cfg *config.Config) map[string]bool {
	ips := make(map[string]bool)

	lines := tailFile("/var/log/secure", 50)
	for _, line := range lines {
		if !strings.Contains(line, "Accepted") {
			continue
		}
		parts := strings.Fields(line)
		for i, p := range parts {
			if p == "from" && i+1 < len(parts) {
				ip := parts[i+1]
				if !isInfraIP(ip, cfg.InfraIPs) && ip != "127.0.0.1" {
					ips[ip] = true
				}
			}
		}
	}

	lines = tailFile("/usr/local/cpanel/logs/access_log", 100)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			ip := fields[0]
			if !isInfraIP(ip, cfg.InfraIPs) && ip != "127.0.0.1" && strings.Count(ip, ".") == 3 {
				ips[ip] = true
			}
		}
	}

	return ips
}

// loadAllBlockedIPs returns all IPs currently blocked in CSF deny list
// and CSM's own block state. These IPs are skipped entirely.
func loadAllBlockedIPs(statePath string) map[string]bool {
	blocked := make(map[string]bool)

	// Read CSF deny list
	data, err := os.ReadFile("/etc/csf/csf.deny")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Format: IP # comment  or  IP
			parts := strings.Fields(line)
			if len(parts) > 0 {
				ip := strings.Split(parts[0], "/")[0] // strip CIDR notation
				if strings.Count(ip, ".") == 3 {
					blocked[ip] = true
				}
			}
		}
	}

	// Read CSM block state
	type blockedEntry struct {
		IP        string    `json:"ip"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	type blockFile struct {
		IPs []blockedEntry `json:"ips"`
	}

	data, err = os.ReadFile(filepath.Join(statePath, "blocked_ips.json"))
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
}

func queryAbuseIPDB(client *http.Client, ip, apiKey string) (score int, category string) {
	req, err := http.NewRequest("GET", abuseIPDBEndpoint+"?ipAddress="+ip+"&maxAgeInDays=90", nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return 0, ""
	}

	var result abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, ""
	}

	category = result.Data.UsageType
	if result.Data.ISP != "" {
		category += " (" + result.Data.ISP + ")"
	}
	if result.Data.TotalReports > 0 {
		category += fmt.Sprintf(", %d reports", result.Data.TotalReports)
	}

	return result.Data.AbuseConfidenceScore, category
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
