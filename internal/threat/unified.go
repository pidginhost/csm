package threat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/attackdb"
	"github.com/pidginhost/cpanel-security-monitor/internal/checks"
)

// IPIntelligence is the complete picture of an IP from all sources.
type IPIntelligence struct {
	IP string `json:"ip"`

	// Internal attack history
	AttackRecord *attackdb.IPRecord `json:"attack_record,omitempty"`
	LocalScore   int                `json:"local_score"`

	// ThreatDB (feeds + permanent blocklist)
	InThreatDB     bool   `json:"in_threat_db"`
	ThreatDBSource string `json:"threat_db_source,omitempty"`

	// AbuseIPDB cache
	AbuseScore    int    `json:"abuse_score"`
	AbuseCategory string `json:"abuse_category,omitempty"`

	// Firewall state
	CurrentlyBlocked bool       `json:"currently_blocked"`
	BlockReason      string     `json:"block_reason,omitempty"`
	BlockExpiresAt   *time.Time `json:"block_expires_at,omitempty"`

	// Composite
	UnifiedScore int    `json:"unified_score"`
	Verdict      string `json:"verdict"` // "clean", "suspicious", "malicious", "blocked"
}

// Lookup returns the full intelligence picture for an IP.
// All reads are local (no network calls). Pre-loads shared state files
// once (same as LookupBatch) to avoid re-reading per field.
func Lookup(ip, statePath string) *IPIntelligence {
	abuseCache := loadFullAbuseCache(statePath)
	blockMap := loadFullBlockState(statePath)

	intel := &IPIntelligence{
		IP:         ip,
		AbuseScore: -1, // not cached
	}

	// 1. Attack DB
	if adb := attackdb.Global(); adb != nil {
		if rec := adb.LookupIP(ip); rec != nil {
			intel.AttackRecord = rec
			intel.LocalScore = rec.ThreatScore
		}
	}

	// 2. ThreatDB (feeds + permanent)
	if tdb := checks.GetThreatDB(); tdb != nil {
		if source, found := tdb.Lookup(ip); found {
			intel.InThreatDB = true
			intel.ThreatDBSource = source
		}
	}

	// 3. AbuseIPDB from pre-loaded cache
	if entry, ok := abuseCache[ip]; ok {
		intel.AbuseScore = entry.Score
		intel.AbuseCategory = entry.Category
	}

	// 4. Block state from pre-loaded map
	if bs, ok := blockMap[ip]; ok {
		intel.CurrentlyBlocked = true
		intel.BlockReason = bs.reason
		if !bs.expiresAt.IsZero() {
			t := bs.expiresAt
			intel.BlockExpiresAt = &t
		}
	}

	computeVerdict(intel)
	return intel
}

// LookupBatch returns intelligence for multiple IPs efficiently.
// Pre-loads shared state files once instead of per-IP.
func LookupBatch(ips []string, statePath string) []*IPIntelligence {
	results := make([]*IPIntelligence, len(ips))
	abuseCache := loadFullAbuseCache(statePath)
	blockMap := loadFullBlockState(statePath)

	for i, ip := range ips {
		intel := &IPIntelligence{
			IP:         ip,
			AbuseScore: -1,
		}

		// Attack DB
		if adb := attackdb.Global(); adb != nil {
			if rec := adb.LookupIP(ip); rec != nil {
				intel.AttackRecord = rec
				intel.LocalScore = rec.ThreatScore
			}
		}

		// ThreatDB
		if tdb := checks.GetThreatDB(); tdb != nil {
			if source, found := tdb.Lookup(ip); found {
				intel.InThreatDB = true
				intel.ThreatDBSource = source
			}
		}

		// AbuseIPDB from pre-loaded cache
		if entry, ok := abuseCache[ip]; ok {
			intel.AbuseScore = entry.Score
			intel.AbuseCategory = entry.Category
		}

		// Block state from pre-loaded map
		if bs, ok := blockMap[ip]; ok {
			intel.CurrentlyBlocked = true
			intel.BlockReason = bs.reason
			if !bs.expiresAt.IsZero() {
				t := bs.expiresAt
				intel.BlockExpiresAt = &t
			}
		}

		computeVerdict(intel)
		results[i] = intel
	}
	return results
}

func computeVerdict(intel *IPIntelligence) {
	intel.UnifiedScore = intel.LocalScore
	if intel.AbuseScore > intel.UnifiedScore {
		intel.UnifiedScore = intel.AbuseScore
	}
	if intel.InThreatDB && intel.UnifiedScore < 100 {
		intel.UnifiedScore = 100
	}

	switch {
	case intel.CurrentlyBlocked:
		intel.Verdict = "blocked"
	case intel.UnifiedScore >= 80:
		intel.Verdict = "malicious"
	case intel.UnifiedScore >= 40:
		intel.Verdict = "suspicious"
	default:
		intel.Verdict = "clean"
	}
}

// --- AbuseIPDB cache reader ---

type abuseEntry struct {
	Score    int    `json:"score"`
	Category string `json:"category"`
}

func loadFullAbuseCache(statePath string) map[string]*abuseEntry {
	type cacheEntry struct {
		Score     int       `json:"score"`
		Category  string    `json:"category"`
		CheckedAt time.Time `json:"checked_at"`
	}
	type cacheFile struct {
		Entries map[string]*cacheEntry `json:"entries"`
	}

	result := make(map[string]*abuseEntry)
	data, err := os.ReadFile(filepath.Join(statePath, "reputation_cache.json"))
	if err != nil {
		return result
	}
	var cf cacheFile
	if json.Unmarshal(data, &cf) != nil || cf.Entries == nil {
		return result
	}
	sixHoursAgo := time.Now().Add(-6 * time.Hour)
	for ip, entry := range cf.Entries {
		if entry.CheckedAt.Before(sixHoursAgo) || entry.Score < 0 {
			continue // expired or error sentinel
		}
		result[ip] = &abuseEntry{Score: entry.Score, Category: entry.Category}
	}
	return result
}

// --- Firewall block state reader ---

type blockEntry struct {
	reason    string
	expiresAt time.Time
}

func loadFullBlockState(statePath string) map[string]*blockEntry {
	result := make(map[string]*blockEntry)
	now := time.Now()

	// Firewall engine state (nftables)
	type fwEntry struct {
		IP        string    `json:"ip"`
		Reason    string    `json:"reason"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	type fwState struct {
		Blocked []fwEntry `json:"blocked"`
	}

	if data, err := os.ReadFile(filepath.Join(statePath, "firewall", "state.json")); err == nil {
		var fs fwState
		if json.Unmarshal(data, &fs) == nil {
			for _, entry := range fs.Blocked {
				if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
					result[entry.IP] = &blockEntry{reason: entry.Reason, expiresAt: entry.ExpiresAt}
				}
			}
		}
	}

	// CSM blocked_ips.json
	type csmEntry struct {
		IP        string    `json:"ip"`
		Reason    string    `json:"reason"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	type csmFile struct {
		IPs []csmEntry `json:"ips"`
	}
	if data, err := os.ReadFile(filepath.Join(statePath, "blocked_ips.json")); err == nil {
		var cf csmFile
		if json.Unmarshal(data, &cf) == nil {
			for _, entry := range cf.IPs {
				if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
					if _, exists := result[entry.IP]; !exists {
						result[entry.IP] = &blockEntry{reason: entry.Reason, expiresAt: entry.ExpiresAt}
					}
				}
			}
		}
	}

	return result
}
