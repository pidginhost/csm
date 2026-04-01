package threat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/attackdb"
	"github.com/pidginhost/cpanel-security-monitor/internal/checks"
	"github.com/pidginhost/cpanel-security-monitor/internal/firewall"
	"github.com/pidginhost/cpanel-security-monitor/internal/store"
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
	BlockedAt        *time.Time `json:"blocked_at,omitempty"`
	BlockExpiresAt   *time.Time `json:"block_expires_at,omitempty"`
	BlockPermanent   bool       `json:"block_permanent,omitempty"`

	// GeoIP (populated by API layer, not by Lookup)
	Country     string `json:"country,omitempty"`
	CountryName string `json:"country_name,omitempty"`
	City        string `json:"city,omitempty"`
	ASN         uint   `json:"asn,omitempty"`
	ASOrg       string `json:"as_org,omitempty"`
	Network     string `json:"network,omitempty"`

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
	applyBlockState(intel, blockMap)

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
		applyBlockState(intel, blockMap)

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

func applyBlockState(intel *IPIntelligence, blockMap map[string]*blockEntry) {
	bs, ok := blockMap[intel.IP]
	if !ok {
		return
	}
	intel.CurrentlyBlocked = true
	intel.BlockReason = bs.reason
	intel.BlockPermanent = bs.permanent
	if !bs.blockedAt.IsZero() {
		t := bs.blockedAt
		intel.BlockedAt = &t
	}
	if !bs.expiresAt.IsZero() && bs.expiresAt.Year() > 1 {
		t := bs.expiresAt
		intel.BlockExpiresAt = &t
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
	blockedAt time.Time
	expiresAt time.Time
	permanent bool
}

func loadFullBlockState(statePath string) map[string]*blockEntry {
	result := make(map[string]*blockEntry)
	now := time.Now()

	// Try bbolt store first.
	if sdb := store.Global(); sdb != nil {
		ss := sdb.LoadFirewallState()
		for _, entry := range ss.Blocked {
			perm := entry.ExpiresAt.IsZero() || entry.ExpiresAt.Year() <= 1
			result[entry.IP] = &blockEntry{
				reason:    entry.Reason,
				blockedAt: entry.BlockedAt,
				expiresAt: entry.ExpiresAt,
				permanent: perm,
			}
		}
	} else {
		// Fallback: firewall.LoadState() reads flat-file state.json.
		fwState, err := firewall.LoadState(statePath)
		if err == nil && fwState != nil {
			for _, entry := range fwState.Blocked {
				perm := entry.ExpiresAt.IsZero() || entry.ExpiresAt.Year() <= 1
				result[entry.IP] = &blockEntry{
					reason:    entry.Reason,
					blockedAt: entry.BlockedAt,
					expiresAt: entry.ExpiresAt,
					permanent: perm,
				}
			}
		}
	}

	// CSM blocked_ips.json (legacy)
	type csmEntry struct {
		IP        string    `json:"ip"`
		Reason    string    `json:"reason"`
		BlockedAt time.Time `json:"blocked_at"`
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
						perm := entry.ExpiresAt.IsZero() || entry.ExpiresAt.Year() <= 1
						result[entry.IP] = &blockEntry{
							reason:    entry.Reason,
							blockedAt: entry.BlockedAt,
							expiresAt: entry.ExpiresAt,
							permanent: perm,
						}
					}
				}
			}
		}
	}

	return result
}
