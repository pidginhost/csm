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
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

func CheckShadowChanges(cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	info, err := os.Stat("/etc/shadow")
	if err != nil {
		return nil
	}

	mtime := info.ModTime()
	key := "_shadow_mtime"
	entry, exists := store.GetRaw(key)

	if exists {
		var lastMtime time.Time
		if err := json.Unmarshal([]byte(entry), &lastMtime); err == nil {
			if mtime.After(lastMtime) {
				// Check if within upcp window
				suppressed := false
				if cfg.Suppressions.UPCPWindowStart != "" {
					now := time.Now()
					h, m := now.Hour(), now.Minute()
					nowMin := h*60 + m
					start := parseTimeMin(cfg.Suppressions.UPCPWindowStart)
					end := parseTimeMin(cfg.Suppressions.UPCPWindowEnd)
					if nowMin >= start && nowMin <= end {
						suppressed = true
					}
				}

				sev := alert.Critical
				if suppressed {
					sev = alert.Warning
				}

				findings = append(findings, alert.Finding{
					Severity: sev,
					Check:    "shadow_change",
					Message:  "/etc/shadow modified",
					Details: fmt.Sprintf("Previous: %s\nCurrent: %s",
						lastMtime.Format("2006-01-02 15:04:05"),
						mtime.Format("2006-01-02 15:04:05")),
				})
			}
		}
	}

	data, _ := json.Marshal(mtime)
	store.SetRaw(key, string(data))

	return findings
}

func CheckUID0Accounts(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	data, err := os.ReadFile("/etc/passwd")
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

func CheckSSHKeys(cfg *config.Config, store *state.Store) []alert.Finding {
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
	homes, _ := filepath.Glob("/home/*/.ssh/authorized_keys")
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

func CheckAPITokens(cfg *config.Config, store *state.Store) []alert.Finding {
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

	// User API tokens — check all accounts
	userDirs, _ := filepath.Glob("/var/cpanel/users/*")
	for _, userFile := range userDirs {
		user := filepath.Base(userFile)
		out, err := runCmd("uapi", "--user="+user, "Tokens", "list")
		if err != nil {
			continue
		}

		// Check for suspicious tokens
		outStr := string(out)
		if strings.Contains(outStr, "has_full_access: 1") {
			// Check if it has no IP whitelist
			if strings.Contains(outStr, "whitelist_ips: ~") || strings.Contains(outStr, "whitelist_ips: \n") {
				// Check if token name is known
				known := false
				for _, t := range cfg.Suppressions.KnownAPITokens {
					if strings.Contains(outStr, "name: "+t) {
						known = true
						break
					}
				}
				if !known {
					// Verify the token IP isn't in infra range
					findings = append(findings, alert.Finding{
						Severity: alert.High,
						Check:    "api_tokens",
						Message:  fmt.Sprintf("User %s has full-access API token with no IP whitelist", user),
						Details:  "This could be attacker-created. Review with: uapi --user=" + user + " Tokens list",
					})
				}
			}
		}
	}

	return findings
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
