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

// State files drive suppression of reputation and auto-block alerts.
// Parse failures must degrade open so corrupt state never hides
// operator-facing findings; warning logs keep the corruption visible.
// Missing state files stay silent because they are normal before the
// first block.

// FilterBlockedAlerts removes reputation and auto-block alerts for IPs
// that are currently blocked in CSM firewall (either just blocked or previously blocked).
func FilterBlockedAlerts(cfg *config.Config, findings []Finding) []Finding {
	if !cfg.Suppressions.SuppressBlockedAlerts {
		return findings
	}

	// Load all currently blocked IPs and queued blocks from state.
	blockedIPs, pendingIPs := loadBlockedAlertState(cfg.StatePath)

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
	for ip := range pendingIPs {
		blockedIPs[ip] = true
	}

	if len(blockedIPs) == 0 && len(blockedSubnets) == 0 {
		return findings
	}

	// Canonicalize blocked-IP keys via net.ParseIP so equality survives
	// notation differences (2001:db8::1 vs 2001:db8:0:0:0:0:0:1,
	// IPv4-mapped IPv6). Keys that do not parse as an IP cannot
	// exact-match a finding's IP and are dropped.
	canonicalBlocked := make(map[string]bool, len(blockedIPs))
	for ip := range blockedIPs {
		if parsed := net.ParseIP(ip); parsed != nil {
			canonicalBlocked[parsed.String()] = true
		}
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
			// Check if the finding's IP is already blocked. Structured
			// SourceIP wins when present; older findings fall back to the
			// message token. The address is compared canonically:
			// substring matching used to let a blocked 1.2.3.4 suppress a
			// finding about the unrelated 1.2.3.45. A finding with no
			// parseable IP is never suppressed (fail open to alerting).
			isBlocked := false
			findingIP := suppressionIPFromFinding(f)
			if findingIP != nil && canonicalBlocked[findingIP.String()] {
				isBlocked = true
			}
			// Also suppress if the IP falls within a freshly-blocked subnet.
			// AUTO-BLOCK-SUBNET: findings from the same batch must silence
			// per-IP reputation alerts for addresses inside that /24.
			if !isBlocked && findingIP != nil {
				for _, subnet := range blockedSubnets {
					if subnet.Contains(findingIP) {
						isBlocked = true
						break
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

func suppressionIPFromFinding(f Finding) net.IP {
	if strings.TrimSpace(f.SourceIP) != "" {
		if normalized := normalizeFindingIP(f.SourceIP); normalized != "" {
			return net.ParseIP(normalized)
		}
		return nil
	}
	return extractIPFromFindingMessage(f.Message)
}

// extractIPFromFindingMessage scans a finding message for the first token
// that parses as a valid IP address and returns it. Returns nil if no IP
// is found. Used to match reputation findings against blocked IPs and
// blocked-subnet CIDRs.
func extractIPFromFindingMessage(msg string) net.IP {
	for _, field := range strings.Fields(msg) {
		if ip := parseIPMessageField(field); ip != nil {
			return ip
		}
	}
	return nil
}

func parseIPMessageField(field string) net.IP {
	if ip := parseIPMessageToken(field); ip != nil {
		return ip
	}
	// Accept key=value tokens such as "ip=5.5.5.5". IP literals never
	// contain '=', so taking the value side cannot mangle a real IP.
	if idx := strings.LastIndexByte(field, '='); idx >= 0 {
		return parseIPMessageToken(field[idx+1:])
	}
	return nil
}

func parseIPMessageToken(token string) net.IP {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}

	if ip := parseNormalizedIP(token); ip != nil {
		return ip
	}

	unquoted := strings.Trim(token, "\"'`")
	if ip := parseNormalizedIP(unquoted); ip != nil {
		return ip
	}

	withoutTrailing := strings.TrimRight(unquoted, ",;")
	if ip := parseNormalizedIP(withoutTrailing); ip != nil {
		return ip
	}

	unwrapped := strings.Trim(withoutTrailing, "()[]{}<>")
	if ip := parseNormalizedIP(unwrapped); ip != nil {
		return ip
	}

	if strings.HasSuffix(unwrapped, ":") {
		withoutColon := strings.TrimSuffix(unwrapped, ":")
		if ip := parseNormalizedIP(withoutColon); ip != nil {
			return ip
		}
		if ip := parseNormalizedIP(strings.Trim(withoutColon, "()[]{}<>")); ip != nil {
			return ip
		}
	}

	return nil
}

func parseNormalizedIP(raw string) net.IP {
	if normalized := normalizeFindingIP(raw); normalized != "" {
		return net.ParseIP(normalized)
	}
	return nil
}

// loadPendingIPs reads IPs queued for blocking from blocked_ips.json.
func loadPendingIPs(statePath string) map[string]bool {
	ips := make(map[string]bool)
	loadBlockFileEntries(statePath, time.Time{}, nil, ips, blockFilePendingSection)
	return ips
}

func loadBlockedIPSource(statePath string, now time.Time, ips map[string]bool) {
	// Use injected loader (bbolt-backed) when available.
	if BlockedIPsFunc != nil {
		for ip, v := range BlockedIPsFunc() {
			ips[ip] = v
		}
		return
	}

	loadFirewallStateFile(statePath, now, ips)
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
	loadBlockedIPSource(statePath, now, ips)
	loadBlockFileEntries(statePath, now, ips, nil, blockFileIPsSection)
	return ips
}

func loadBlockedAlertState(statePath string) (map[string]bool, map[string]bool) {
	ips := make(map[string]bool)
	pending := make(map[string]bool)
	now := time.Now()
	loadBlockedIPSource(statePath, now, ips)
	loadBlockFileEntries(statePath, now, ips, pending, blockFileIPsSection|blockFilePendingSection)
	return ips, pending
}

func loadFirewallStateFile(statePath string, now time.Time, ips map[string]bool) {
	fwPath := filepath.Join(statePath, "firewall", "state.json")
	fwData, err := os.ReadFile(fwPath) // #nosec G304 -- filepath.Join under operator-configured statePath.
	if err != nil {
		return
	}

	var fwState struct {
		Blocked []struct {
			IP        string    `json:"ip"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"blocked"`
	}
	if err := json.Unmarshal(fwData, &fwState); err != nil {
		csmlog.Warn("alert filter: firewall state.json unparseable, suppression degraded",
			"path", fwPath, "err", err)
		return
	}

	for _, entry := range fwState.Blocked {
		if entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt) {
			ips[entry.IP] = true
		}
	}
}

type blockFile struct {
	IPs     []blockFileIP
	Pending []blockFilePendingIP
}

type blockFileIP struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
}

type blockFilePendingIP struct {
	IP string `json:"ip"`
}

type blockFileSection uint8

const (
	blockFileIPsSection blockFileSection = 1 << iota
	blockFilePendingSection
)

func loadBlockFileEntries(statePath string, now time.Time, ips map[string]bool, pending map[string]bool, sections blockFileSection) {
	bf, ok := loadBlockFile(statePath, sections)
	if !ok {
		return
	}

	for _, entry := range bf.IPs {
		if ips != nil && (entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt)) {
			ips[entry.IP] = true
		}
	}
	for _, entry := range bf.Pending {
		if pending != nil {
			pending[entry.IP] = true
		}
	}
}

func loadBlockFile(statePath string, sections blockFileSection) (blockFile, bool) {
	blockedPath := filepath.Join(statePath, "blocked_ips.json")
	data, err := os.ReadFile(blockedPath) // #nosec G304 -- filepath.Join under operator-configured statePath.
	if err != nil {
		return blockFile{}, false
	}

	var raw struct {
		IPs     json.RawMessage `json:"ips"`
		Pending json.RawMessage `json:"pending"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		csmlog.Warn("alert filter: blocked_ips.json unparseable, suppression degraded",
			"path", blockedPath, "err", err)
		return blockFile{}, false
	}

	var bf blockFile
	if sections&blockFileIPsSection != 0 && len(raw.IPs) > 0 && string(raw.IPs) != "null" {
		if err := json.Unmarshal(raw.IPs, &bf.IPs); err != nil {
			csmlog.Warn("alert filter: blocked_ips.json blocked entries unparseable, suppression degraded",
				"path", blockedPath, "err", err)
		}
	}
	if sections&blockFilePendingSection != 0 && len(raw.Pending) > 0 && string(raw.Pending) != "null" {
		if err := json.Unmarshal(raw.Pending, &bf.Pending); err != nil {
			csmlog.Warn("alert filter: blocked_ips.json pending entries unparseable, suppression degraded",
				"path", blockedPath, "err", err)
		}
	}

	return bf, true
}
