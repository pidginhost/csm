package alert

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// fail-closed audit (2026-05-23): the JSON state files this package
// reads (`blocked_ips.json`, firewall `state.json`) drive suppression
// of reputation and auto-block alerts. When parsing fails, the loaders
// return an empty map, which causes FilterBlockedAlerts to suppress
// nothing -- alerts still reach the operator. That is the right
// failure mode (no false-negatives on the operator-facing channel),
// but the silence on json.Unmarshal failures hides corruption that an
// operator would want to know about. The Unmarshal errors now log via
// csmlog.Warn. Read errors stay silent because absent state files are
// the normal pre-first-block state, not corruption.

// FilterBlockedAlerts removes reputation and auto-block alerts for IPs
// that are currently blocked in CSM firewall (either just blocked or previously blocked).
func FilterBlockedAlerts(cfg *config.Config, findings []Finding) []Finding {
	if !cfg.Suppressions.SuppressBlockedAlerts {
		return findings
	}

	// Load all currently blocked IPs from state
	blockedIPs := loadBlockedIPs(cfg.StatePath)

	// Also collect IPs and subnets blocked in this batch.
	var blockedSubnets []*net.IPNet
	for _, f := range findings {
		if f.Check != "auto_block" {
			continue
		}
		parts := strings.Fields(f.Message)
		for i, p := range parts {
			if p == "AUTO-BLOCK:" && i+1 < len(parts) {
				blockedIPs[parts[i+1]] = true
				break
			}
			if p == "AUTO-BLOCK-SUBNET:" && i+1 < len(parts) {
				if _, ipnet, err := net.ParseCIDR(parts[i+1]); err == nil {
					blockedSubnets = append(blockedSubnets, ipnet)
				}
				break
			}
		}
	}

	// Also suppress alerts for IPs queued for blocking (rate-limited).
	// These will be blocked once the rate limit resets - no need to alert.
	for ip := range loadPendingIPs(cfg.StatePath) {
		blockedIPs[ip] = true
	}

	if len(blockedIPs) == 0 && len(blockedSubnets) == 0 {
		return findings
	}

	// Filter out alerts for IPs that are handled automatically.
	// When suppress_blocked_alerts is on, the operator doesn't want to be
	// notified about IPs that are already dealt with - they only want alerts
	// that require human action.
	var filtered []Finding
	for _, f := range findings {
		if f.Check == "ip_reputation" || f.Check == "local_threat_score" {
			// If auto-blocking is enabled, these IPs are handled automatically.
			// Skip the alert - there's nothing for the operator to do.
			if cfg.AutoResponse.Enabled && cfg.AutoResponse.BlockIPs {
				continue
			}
			// Check if the IP is already blocked by exact IP match.
			isBlocked := false
			for ip := range blockedIPs {
				if strings.Contains(f.Message, ip) {
					isBlocked = true
					break
				}
			}
			// Also suppress if the IP falls within a freshly-blocked subnet.
			// AUTO-BLOCK-SUBNET: findings from the same batch must silence
			// per-IP reputation alerts for addresses inside that /24.
			if !isBlocked && len(blockedSubnets) > 0 {
				if parsed := extractIPFromFindingMessage(f.Message); parsed != nil {
					for _, subnet := range blockedSubnets {
						if subnet.Contains(parsed) {
							isBlocked = true
							break
						}
					}
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

// extractIPFromFindingMessage scans a finding message for the first token
// that parses as a valid IP address and returns it. Returns nil if no IP
// is found. Used to match reputation findings against blocked-subnet CIDRs.
func extractIPFromFindingMessage(msg string) net.IP {
	for _, field := range strings.Fields(msg) {
		// Strip common punctuation that may trail an IP in a message.
		candidate := strings.TrimRight(field, ",:;)([]")
		if ip := net.ParseIP(candidate); ip != nil {
			return ip
		}
	}
	return nil
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
	// #nosec G304 -- filepath.Join under operator-configured statePath.
	pendingPath := filepath.Join(statePath, "blocked_ips.json")
	data, err := os.ReadFile(pendingPath)
	if err == nil {
		var bf blockFile
		if unmErr := json.Unmarshal(data, &bf); unmErr == nil {
			for _, p := range bf.Pending {
				ips[p.IP] = true
			}
		} else {
			csmlog.Warn("alert filter: blocked_ips.json (pending) unparseable, suppression degraded",
				"path", pendingPath, "err", unmErr)
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
		// #nosec G304 -- filepath.Join under operator-configured statePath.
		fwPath := filepath.Join(statePath, "firewall", "state.json")
		if fwData, err := os.ReadFile(fwPath); err == nil {
			var fwState struct {
				Blocked []struct {
					IP        string    `json:"ip"`
					ExpiresAt time.Time `json:"expires_at"`
				} `json:"blocked"`
			}
			if unmErr := json.Unmarshal(fwData, &fwState); unmErr == nil {
				for _, entry := range fwState.Blocked {
					if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
						ips[entry.IP] = true
					}
				}
			} else {
				csmlog.Warn("alert filter: firewall state.json unparseable, suppression degraded",
					"path", fwPath, "err", unmErr)
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

	// #nosec G304 -- filepath.Join under operator-configured statePath.
	blockedPath := filepath.Join(statePath, "blocked_ips.json")
	if data, err := os.ReadFile(blockedPath); err == nil {
		var bf blockFile
		if unmErr := json.Unmarshal(data, &bf); unmErr == nil {
			for _, entry := range bf.IPs {
				if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
					ips[entry.IP] = true
				}
			}
		} else {
			csmlog.Warn("alert filter: blocked_ips.json unparseable, suppression degraded",
				"path", blockedPath, "err", unmErr)
		}
	}

	return ips
}
