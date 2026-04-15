package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func CheckShadowChanges(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	info, err := osFS.Stat("/etc/shadow")
	if err != nil {
		return nil
	}

	mtime := info.ModTime()
	mtimeKey := "_shadow_mtime"
	hashKey := "_shadow_hash"

	// Load current shadow entries (user:hash pairs, no sensitive data stored)
	currentEntries := parseShadowUsers()
	currentHash := hashBytes([]byte(fmt.Sprintf("%v", currentEntries)))

	prevMtimeRaw, mtimeExists := store.GetRaw(mtimeKey)
	prevHash, hashExists := store.GetRaw(hashKey)

	if mtimeExists {
		var lastMtime time.Time
		if err := json.Unmarshal([]byte(prevMtimeRaw), &lastMtime); err == nil {
			if mtime.After(lastMtime) {
				// Shadow file was modified - find what changed
				var details string
				if hashExists && prevHash != currentHash {
					changed := diffShadowChanges(store, currentEntries)
					if len(changed) > 0 {
						details = fmt.Sprintf("Previous: %s\nCurrent: %s\nAccounts changed: %s",
							lastMtime.Format("2006-01-02 15:04:05"),
							mtime.Format("2006-01-02 15:04:05"),
							strings.Join(changed, ", "))
					}
				}
				if details == "" {
					details = fmt.Sprintf("Previous: %s\nCurrent: %s",
						lastMtime.Format("2006-01-02 15:04:05"),
						mtime.Format("2006-01-02 15:04:05"))
				}

				// Check if within upcp window
				sev := alert.Critical
				if cfg.Suppressions.UPCPWindowStart != "" {
					now := time.Now()
					h, m := now.Hour(), now.Minute()
					nowMin := h*60 + m
					start := parseTimeMin(cfg.Suppressions.UPCPWindowStart)
					end := parseTimeMin(cfg.Suppressions.UPCPWindowEnd)
					if nowMin >= start && nowMin <= end {
						sev = alert.Warning
					}
				}

				// Check auditd for who made the change
				auditInfo := getAuditShadowInfo()
				if auditInfo != "" {
					details += "\n" + auditInfo
				}

				// Suppress alerts for password changes made by infra IPs
				// (admin-initiated password resets via WHM/xml-api)
				if isInfraShadowChange(cfg) {
					// Still update state, but don't alert
					goto storeState
				}

				// Separate root password change (higher severity)
				changed := diffShadowChanges(store, currentEntries)
				rootChanged := false
				userCount := 0
				for _, c := range changed {
					if c == "root" {
						rootChanged = true
					} else {
						userCount++
					}
				}

				if rootChanged {
					findings = append(findings, alert.Finding{
						Severity: alert.Critical,
						Check:    "root_password_change",
						Message:  "Root password changed",
						Details:  details,
					})
				}

				// Bulk password changes (5+ accounts at once)
				if userCount >= 5 {
					findings = append(findings, alert.Finding{
						Severity: alert.High,
						Check:    "bulk_password_change",
						Message:  fmt.Sprintf("Bulk password change: %d accounts modified", userCount),
						Details:  details,
					})
				} else {
					findings = append(findings, alert.Finding{
						Severity: sev,
						Check:    "shadow_change",
						Message:  "/etc/shadow modified",
						Details:  details,
					})
				}
			}
		}
	}

storeState:
	// Store current state
	mtimeData, _ := json.Marshal(mtime)
	store.SetRaw(mtimeKey, string(mtimeData))
	store.SetRaw(hashKey, currentHash)

	// Store per-user hashes for diff next time
	for user, hash := range currentEntries {
		store.SetRaw("_shadow_user:"+user, hash)
	}

	return findings
}

// parseShadowUsers reads /etc/shadow and returns a map of user -> password hash.
// Only stores a hash of the hash, not the actual password hash.
func parseShadowUsers() map[string]string {
	data, err := osFS.ReadFile("/etc/shadow")
	if err != nil {
		return nil
	}
	entries := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		// Store a hash of the password field, not the field itself
		entries[parts[0]] = hashBytes([]byte(parts[1]))
	}
	return entries
}

// diffShadowChanges compares current entries against stored per-user hashes.
func diffShadowChanges(store *state.Store, current map[string]string) []string {
	var changed []string
	for user, hash := range current {
		prev, exists := store.GetRaw("_shadow_user:" + user)
		if exists && prev != hash {
			changed = append(changed, user)
		} else if !exists {
			changed = append(changed, user+" (new)")
		}
	}
	return changed
}

// getAuditShadowInfo checks auditd for recent shadow change events.
func getAuditShadowInfo() string {
	out, err := runCmd("grep", "csm_shadow_change", "/var/log/audit/audit.log")
	if err != nil || len(out) == 0 {
		return ""
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return ""
	}

	// Get the last event
	last := lines[len(lines)-1]

	// Extract exe= field
	exe := ""
	for _, part := range strings.Fields(last) {
		if strings.HasPrefix(part, "exe=") {
			exe = strings.Trim(strings.TrimPrefix(part, "exe="), "\"")
			break
		}
	}

	// Decode hex comm if present
	comm := ""
	for _, part := range strings.Fields(last) {
		if strings.HasPrefix(part, "comm=") {
			raw := strings.Trim(strings.TrimPrefix(part, "comm="), "\"")
			decoded := decodeHexString(raw)
			if decoded != "" {
				comm = decoded
			} else {
				comm = raw
			}
			break
		}
	}

	if exe != "" || comm != "" {
		return fmt.Sprintf("Changed by: %s (command: %s)", exe, comm)
	}
	return ""
}

// decodeHexString tries to decode a hex-encoded string (auditd encodes some comm fields).
func decodeHexString(s string) string {
	if len(s)%2 != 0 || len(s) < 4 {
		return ""
	}
	// Check if it looks like hex (all hex chars)
	for _, c := range s {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return ""
		}
	}
	var result []byte
	for i := 0; i < len(s); i += 2 {
		// #nosec G115 -- hexVal returns 0..15; (h<<4)|h fits in a byte.
		b := byte(hexVal(s[i])<<4 | hexVal(s[i+1]))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	if len(result) == 0 {
		return ""
	}
	return string(result)
}

func CheckUID0Accounts(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	data, err := osFS.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}

	allowedUID0 := map[string]bool{
		"root": true, "sync": true, "shutdown": true,
		"halt": true, "operator": true,
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		user := fields[0]
		uid := fields[2]
		if uid == "0" && !allowedUID0[user] {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "uid0_account",
				Message:  fmt.Sprintf("Unauthorized UID 0 account: %s", user),
				Details:  line,
			})
		}
	}

	return findings
}

func CheckSSHKeys(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Check root authorized_keys
	rootKeys := "/root/.ssh/authorized_keys"
	if hash, err := hashFileContent(rootKeys); err == nil {
		key := "_ssh_root_keys_hash"
		prev, exists := store.GetRaw(key)
		if exists && prev != hash {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "ssh_keys",
				Message:  "Root authorized_keys modified",
				Details:  fmt.Sprintf("File: %s", rootKeys),
			})
		}
		store.SetRaw(key, hash)
	}

	// Check for new authorized_keys in /home
	homes, _ := osFS.Glob("/home/*/.ssh/authorized_keys")
	for _, keyFile := range homes {
		hash, err := hashFileContent(keyFile)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("_ssh_user_keys:%s", keyFile)
		prev, exists := store.GetRaw(key)
		if exists && prev != hash {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "ssh_keys",
				Message:  fmt.Sprintf("User authorized_keys modified: %s", keyFile),
			})
		}
		store.SetRaw(key, hash)
	}

	return findings
}

func CheckAPITokens(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	// WHM root API tokens
	out, err := runCmd("whmapi1", "api_token_list")
	if err == nil {
		hash := hashBytes(out)
		key := "_whm_api_tokens_hash"
		prev, exists := store.GetRaw(key)
		if exists && prev != hash {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "api_tokens",
				Message:  "WHM root API tokens changed",
				Details:  "Run 'whmapi1 api_token_list' to review",
			})
		}
		store.SetRaw(key, hash)
	}

	// User API tokens - read directly from disk instead of spawning uapi per user
	// Token files are JSON at /home/<user>/.cpanel/api_tokens/<token_name>
	tokenDirs, _ := osFS.Glob("/home/*/.cpanel/api_tokens")
	for _, tokenDir := range tokenDirs {
		user := filepath.Base(filepath.Dir(filepath.Dir(tokenDir)))
		tokenFiles, _ := osFS.Glob(filepath.Join(tokenDir, "*"))
		for _, tokenFile := range tokenFiles {
			tokenName := filepath.Base(tokenFile)
			data, err := osFS.ReadFile(tokenFile)
			if err != nil {
				continue
			}
			content := string(data)

			// Check for full access with no IP whitelist
			hasFullAccess := strings.Contains(content, `"has_full_access":1`) ||
				strings.Contains(content, `"has_full_access": 1`)
			noWhitelist := strings.Contains(content, `"whitelist_ips":null`) ||
				strings.Contains(content, `"whitelist_ips": null`) ||
				strings.Contains(content, `"whitelist_ips":[]`) ||
				strings.Contains(content, `"whitelist_ips": []`) ||
				!strings.Contains(content, "whitelist_ips")

			if hasFullAccess && noWhitelist {
				known := false
				for _, t := range cfg.Suppressions.KnownAPITokens {
					if tokenName == t {
						known = true
						break
					}
				}
				if !known {
					findings = append(findings, alert.Finding{
						Severity: alert.High,
						Check:    "api_tokens",
						Message:  fmt.Sprintf("User %s has full-access API token '%s' with no IP whitelist", user, tokenName),
						Details:  fmt.Sprintf("File: %s", tokenFile),
					})
				}
			}
		}
	}

	return findings
}

// isInfraShadowChange checks the cPanel session log for recent password
// change PURGE events from infra IPs. This is more reliable than the
// access log because it captures the actual IP that triggered the change.
//
// Returns true only if ALL recent password purges came from infra IPs.
// If any came from non-infra → returns false (possible attack).
func isInfraShadowChange(cfg *config.Config) bool {
	lines := tailFile("/usr/local/cpanel/logs/session_log", 100)

	foundAny := false
	allInfra := true

	// Check recent PURGE password_change events (last ~5 minutes of log)
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]

		if !strings.Contains(line, "PURGE") || !strings.Contains(line, "password_change") {
			continue
		}

		foundAny = true

		// Extract IP from session log
		// Format: [timestamp] info [xml-api] IP PURGE account:token password_change
		// Format: [timestamp] info [whostmgr] IP PURGE account:token password_change
		var ip string
		for _, tag := range []string{"[xml-api]", "[whostmgr]", "[security]"} {
			if idx := strings.Index(line, tag); idx >= 0 {
				rest := strings.TrimSpace(line[idx+len(tag):])
				fields := strings.Fields(rest)
				if len(fields) > 0 {
					ip = fields[0]
				}
				break
			}
		}

		if ip == "" || ip == "internal" {
			continue // internal events are safe
		}

		if !isInfraIP(ip, cfg.InfraIPs) && ip != "127.0.0.1" {
			allInfra = false
			break // found a non-infra password change - don't suppress
		}
	}

	return foundAny && allInfra
}

func parseTimeMin(s string) int {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0
	}
	h := 0
	m := 0
	fmt.Sscanf(parts[0], "%d", &h)
	fmt.Sscanf(parts[1], "%d", &m)
	return h*60 + m
}
