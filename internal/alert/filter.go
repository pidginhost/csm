package alert

import (
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

// FilterBlockedAlerts removes reputation alerts for IPs that were auto-blocked,
// if suppress_blocked_alerts is enabled. Keeps the auto_block action itself
// only if suppress is off.
func FilterBlockedAlerts(cfg *config.Config, findings []Finding) []Finding {
	if !cfg.Suppressions.SuppressBlockedAlerts {
		return findings
	}

	// Collect IPs that were auto-blocked
	blockedIPs := make(map[string]bool)
	for _, f := range findings {
		if f.Check == "auto_block" && strings.Contains(f.Message, "AUTO-BLOCK:") {
			// Extract IP from "AUTO-BLOCK: X.X.X.X blocked in CSF"
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

	// Filter out reputation alerts for blocked IPs AND the auto_block actions themselves
	var filtered []Finding
	for _, f := range findings {
		if f.Check == "ip_reputation" {
			// Check if this IP was blocked
			isBlocked := false
			for ip := range blockedIPs {
				if strings.Contains(f.Message, ip) {
					isBlocked = true
					break
				}
			}
			if isBlocked {
				continue // skip — IP was handled by auto-block
			}
		}
		if f.Check == "auto_block" && strings.Contains(f.Message, "AUTO-BLOCK:") {
			continue // skip auto-block notifications too
		}
		filtered = append(filtered, f)
	}

	return filtered
}
