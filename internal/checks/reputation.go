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

// CheckIPReputation looks up non-infra IPs from recent findings against
// AbuseIPDB threat intelligence. Flags IPs with high abuse confidence scores.
func CheckIPReputation(cfg *config.Config, _ *state.Store) []alert.Finding {
	if cfg.Reputation.AbuseIPDBKey == "" {
		return nil
	}

	var findings []alert.Finding

	// Collect unique non-infra IPs from recent log activity
	ips := collectRecentIPs(cfg)
	if len(ips) == 0 {
		return nil
	}

	// Load reputation cache
	cache := loadReputationCache(cfg.StatePath)

	client := &http.Client{Timeout: 10 * time.Second}

	checked := 0
	for ip := range ips {
		// Skip if cached and fresh
		if entry, ok := cache.Entries[ip]; ok {
			if time.Since(entry.CheckedAt) < cacheExpiry {
				if entry.Score >= abuseConfidenceThreshold {
					findings = append(findings, alert.Finding{
						Severity: alert.High,
						Check:    "ip_reputation",
						Message:  fmt.Sprintf("Known malicious IP active: %s (AbuseIPDB score: %d)", ip, entry.Score),
						Details:  fmt.Sprintf("Category: %s", entry.Category),
					})
				}
				continue
			}
		}

		// Rate limit — max 10 lookups per check cycle
		if checked >= 10 {
			break
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
				Severity: alert.Critical,
				Check:    "ip_reputation",
				Message:  fmt.Sprintf("Known malicious IP accessing server: %s (AbuseIPDB score: %d/100)", ip, score),
				Details:  fmt.Sprintf("Category: %s\nThis IP is reported in threat intelligence databases", category),
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

	// From SSH logins
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

	// From cPanel access log
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
