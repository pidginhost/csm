package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

const (
	maxBlocksPerHour   = 50
	defaultBlockExpiry = "24h"
	blockStateFile     = "blocked_ips.json"
)

type blockedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type blockState struct {
	IPs            []blockedIP `json:"ips"`
	BlocksThisHour int         `json:"blocks_this_hour"`
	HourKey        string      `json:"hour_key"`
}

// AutoBlockIPs processes findings and blocks attacker IPs via CSF.
// Only blocks IPs that triggered CRITICAL or HIGH findings related to
// brute force, unauthorized access, or active attacks.
func AutoBlockIPs(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	if !cfg.AutoResponse.Enabled || !cfg.AutoResponse.BlockIPs {
		return nil
	}

	var actions []alert.Finding

	// Load block state
	state := loadBlockState(cfg.StatePath)

	// Check rate limit
	currentHour := time.Now().Format("2006-01-02T15")
	if state.HourKey != currentHour {
		state.HourKey = currentHour
		state.BlocksThisHour = 0
	}

	// Collect IPs to block from findings
	ipsToBlock := make(map[string]string) // ip -> reason

	blockableChecks := map[string]bool{
		"wp_login_bruteforce":         true,
		"xmlrpc_abuse":                true,
		"ftp_bruteforce":              true,
		"webmail_bruteforce":          true,
		"api_auth_failure":            true,
		"ssh_login_unknown_ip":        true,
		"ssh_login_realtime":          true,
		"cpanel_login":                true,
		"cpanel_login_realtime":       true,
		"cpanel_multi_ip_login":       true,
		"cpanel_file_upload_realtime": true,
		"ftp_login_realtime":          true,
		"ftp_auth_failure_realtime":   true,
		"api_auth_failure_realtime":   true,
		"c2_connection":               true,
	}

	for _, f := range findings {
		if !blockableChecks[f.Check] {
			continue
		}

		ip := extractIPFromFinding(f)
		if ip == "" {
			continue
		}

		// Never block infra IPs
		if isInfraIP(ip, cfg.InfraIPs) || ip == "127.0.0.1" {
			continue
		}

		// Don't re-block already blocked IPs
		if isAlreadyBlocked(state, ip) {
			continue
		}

		ipsToBlock[ip] = f.Message
	}

	// Block IPs
	expiry := parseExpiry(cfg.AutoResponse.BlockExpiry)
	for ip, reason := range ipsToBlock {
		if state.BlocksThisHour >= maxBlocksPerHour {
			actions = append(actions, alert.Finding{
				Severity:  alert.Warning,
				Check:     "auto_block",
				Message:   fmt.Sprintf("Auto-block rate limit reached (%d/hour), skipping IP: %s", maxBlocksPerHour, ip),
				Timestamp: time.Now(),
			})
			break
		}

		// Block via CSF
		csfReason := fmt.Sprintf("CSM auto-block: %s", truncate(reason, 100))
		out, err := runCmd("csf", "-d", ip, csfReason)
		if err != nil && out == nil {
			continue
		}

		state.BlocksThisHour++
		state.IPs = append(state.IPs, blockedIP{
			IP:        ip,
			Reason:    reason,
			BlockedAt: time.Now(),
			ExpiresAt: time.Now().Add(expiry),
		})

		actions = append(actions, alert.Finding{
			Severity:  alert.Critical,
			Check:     "auto_block",
			Message:   fmt.Sprintf("AUTO-BLOCK: %s blocked in CSF (expires in %s)", ip, expiry),
			Details:   fmt.Sprintf("Reason: %s", reason),
			Timestamp: time.Now(),
		})
	}

	// Unblock expired IPs
	var activeIPs []blockedIP
	for _, blocked := range state.IPs {
		if time.Now().After(blocked.ExpiresAt) {
			// Unblock
			_, _ = runCmd("csf", "-dr", blocked.IP)
			actions = append(actions, alert.Finding{
				Severity:  alert.Warning,
				Check:     "auto_block",
				Message:   fmt.Sprintf("AUTO-UNBLOCK: %s removed from CSF (expired)", blocked.IP),
				Timestamp: time.Now(),
			})
		} else {
			activeIPs = append(activeIPs, blocked)
		}
	}
	state.IPs = activeIPs

	// Save state
	saveBlockState(cfg.StatePath, state)

	return actions
}

func extractIPFromFinding(f alert.Finding) string {
	// Try to extract IP from message — look for patterns like "from X.X.X.X" or ": X.X.X.X"
	for _, sep := range []string{" from ", ": "} {
		if idx := strings.Index(f.Message, sep); idx >= 0 {
			rest := f.Message[idx+len(sep):]
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				ip := strings.TrimRight(fields[0], ",:;)([]")
				if len(ip) >= 7 && strings.Count(ip, ".") == 3 {
					return ip
				}
			}
		}
	}
	return ""
}

func isAlreadyBlocked(state *blockState, ip string) bool {
	for _, b := range state.IPs {
		if b.IP == ip {
			return true
		}
	}
	return false
}

func parseExpiry(s string) time.Duration {
	if s == "" {
		s = defaultBlockExpiry
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

func loadBlockState(statePath string) *blockState {
	state := &blockState{}
	data, err := os.ReadFile(filepath.Join(statePath, blockStateFile))
	if err == nil {
		_ = json.Unmarshal(data, state)
	}
	return state
}

func saveBlockState(statePath string, state *blockState) {
	data, _ := json.MarshalIndent(state, "", "  ")
	tmpPath := filepath.Join(statePath, blockStateFile+".tmp")
	_ = os.WriteFile(tmpPath, data, 0600)
	_ = os.Rename(tmpPath, filepath.Join(statePath, blockStateFile))
}
