package alert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// FilterBlockedAlerts removes reputation and auto-block alerts for IPs
// that are currently blocked in CSM firewall (either just blocked or previously blocked).
func FilterBlockedAlerts(cfg *config.Config, findings []Finding) []Finding {
	if !cfg.Suppressions.SuppressBlockedAlerts {
		return findings
	}

	// Load all currently blocked IPs from state
	blockedIPs := loadBlockedIPs(cfg.StatePath)

	// Also collect IPs blocked in this batch
	for _, f := range findings {
		if f.Check == "auto_block" && strings.Contains(f.Message, "AUTO-BLOCK:") {
			parts := strings.Fields(f.Message)
			for i, p := range parts {
				if p == "AUTO-BLOCK:" && i+1 < len(parts) {
					blockedIPs[parts[i+1]] = true
					break
				}
			}
		}
	}

	// Also suppress alerts for IPs queued for blocking (rate-limited).
	// These will be blocked once the rate limit resets — no need to alert.
	for ip := range loadPendingIPs(cfg.StatePath) {
		blockedIPs[ip] = true
	}

	if len(blockedIPs) == 0 {
		return findings
	}

	// Filter out alerts for IPs that are handled automatically.
	// When suppress_blocked_alerts is on, the operator doesn't want to be
	// notified about IPs that are already dealt with — they only want alerts
	// that require human action.
	var filtered []Finding
	for _, f := range findings {
		if f.Check == "ip_reputation" || f.Check == "local_threat_score" {
			// If auto-blocking is enabled, these IPs are handled automatically.
			// Skip the alert — there's nothing for the operator to do.
			if cfg.AutoResponse.Enabled && cfg.AutoResponse.BlockIPs {
				continue
			}
			// Otherwise check if the IP is already blocked (manual block or CSM firewall)
			isBlocked := false
			for ip := range blockedIPs {
				if strings.Contains(f.Message, ip) {
					isBlocked = true
					break
				}
			}
			if isBlocked {
				continue
			}
		}
		if f.Check == "auto_block" {
			continue
		}
		filtered = append(filtered, f)
	}

	return filtered
}

// loadPendingIPs reads IPs queued for blocking from blocked_ips.json.
func loadPendingIPs(statePath string) map[string]bool {
	ips := make(map[string]bool)
	type pending struct {
		IP string `json:"ip"`
	}
	type blockFile struct {
		Pending []pending `json:"pending"`
	}
	data, err := os.ReadFile(filepath.Join(statePath, "blocked_ips.json"))
	if err == nil {
		var bf blockFile
		if json.Unmarshal(data, &bf) == nil {
			for _, p := range bf.Pending {
				ips[p.IP] = true
			}
		}
	}
	return ips
}

// BlockedIPsFunc is an optional callback that returns currently blocked IPs.
// Set by the daemon (or tests) to provide blocked IPs from bbolt store,
// avoiding a circular import between alert and store packages.
// When nil, loadBlockedIPs falls back to reading flat files.
var BlockedIPsFunc func() map[string]bool

// loadBlockedIPs reads blocked IPs from both the firewall engine state
// and the legacy blocked_ips.json file.
func loadBlockedIPs(statePath string) map[string]bool {
	ips := make(map[string]bool)
	now := time.Now()

	// Use injected loader (bbolt-backed) when available.
	if BlockedIPsFunc != nil {
		for ip, v := range BlockedIPsFunc() {
			ips[ip] = v
		}
	} else {
		// Fallback: read from firewall engine state.json (nftables) flat file.
		if fwData, err := os.ReadFile(filepath.Join(statePath, "firewall", "state.json")); err == nil {
			var fwState struct {
				Blocked []struct {
					IP        string    `json:"ip"`
					ExpiresAt time.Time `json:"expires_at"`
				} `json:"blocked"`
			}
			if json.Unmarshal(fwData, &fwState) == nil {
				for _, entry := range fwState.Blocked {
					if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
						ips[entry.IP] = true
					}
				}
			}
		}
	}

	// Also read from blocked_ips.json (CSM auto-block)
	type blockFile struct {
		IPs []struct {
			IP        string    `json:"ip"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"ips"`
	}

	if data, err := os.ReadFile(filepath.Join(statePath, "blocked_ips.json")); err == nil {
		var bf blockFile
		if json.Unmarshal(data, &bf) == nil {
			for _, entry := range bf.IPs {
				if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
					ips[entry.IP] = true
				}
			}
		}
	}

	return ips
}
