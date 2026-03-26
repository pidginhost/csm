package alert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

// FilterBlockedAlerts removes reputation and auto-block alerts for IPs
// that are currently blocked in CSF (either just blocked or previously blocked).
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

	if len(blockedIPs) == 0 {
		return findings
	}

	// Filter out reputation alerts for blocked IPs AND auto_block notifications
	var filtered []Finding
	for _, f := range findings {
		if f.Check == "ip_reputation" {
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
		if f.Check == "auto_block" && strings.Contains(f.Message, "AUTO-BLOCK:") {
			continue
		}
		filtered = append(filtered, f)
	}

	return filtered
}

// loadBlockedIPs reads blocked IPs from both the firewall engine state
// and the legacy blocked_ips.json file.
func loadBlockedIPs(statePath string) map[string]bool {
	ips := make(map[string]bool)
	now := time.Now()

	// Read from firewall engine state (nftables)
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

	// Also read from legacy blocked_ips.json (CSF auto-block)
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
				if now.Before(entry.ExpiresAt) {
					ips[entry.IP] = true
				}
			}
		}
	}

	return ips
}
