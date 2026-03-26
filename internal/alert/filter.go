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

// loadBlockedIPs reads the blocked_ips.json state file and returns
// all IPs that are currently blocked (not expired).
func loadBlockedIPs(statePath string) map[string]bool {
	ips := make(map[string]bool)

	type blockedEntry struct {
		IP        string    `json:"ip"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	type blockFile struct {
		IPs []blockedEntry `json:"ips"`
	}

	data, err := os.ReadFile(filepath.Join(statePath, "blocked_ips.json"))
	if err != nil {
		return ips
	}

	var bf blockFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return ips
	}

	now := time.Now()
	for _, entry := range bf.IPs {
		if now.Before(entry.ExpiresAt) {
			ips[entry.IP] = true
		}
	}

	return ips
}
