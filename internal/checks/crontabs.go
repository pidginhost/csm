package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func CheckCrontabs(ctx context.Context, _ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	suspiciousPatterns := []string{
		"defunct-kernel",
		"SEED PRNG",
		"base64_decode",
		"eval(",
		"/dev/tcp/",
		"gsocket",
		"gs-netcat",
		"reverse",
		"bash -i",
		"/bin/sh -i",
		"nc -e",
		"ncat -e",
		"python -c",
		"perl -e",
	}

	crontabs, _ := osFS.Glob("/var/spool/cron/*")
	for _, path := range crontabs {
		user := filepath.Base(path)
		if user == "root" {
			// Track root crontab changes via hash
			hash, _ := hashFileContent(path)
			key := "_crontab_root_hash"
			prev, exists := store.GetRaw(key)
			if exists && prev != hash {
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "crontab_change",
					Message:  "Root crontab modified",
					Details:  "Review with: crontab -l",
				})
			}
			store.SetRaw(key, hash)
			continue
		}

		data, err := osFS.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)

		for _, pattern := range suspiciousPatterns {
			if strings.Contains(strings.ToLower(content), strings.ToLower(pattern)) {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "suspicious_crontab",
					Message:  fmt.Sprintf("Suspicious pattern in crontab for user %s: %s", user, pattern),
					Details:  fmt.Sprintf("File: %s\nContent:\n%s", path, truncate(content, 500)),
				})
			}
		}
	}

	// Check /etc/cron.d for new files
	cronDFiles, _ := osFS.Glob("/etc/cron.d/*")
	for _, path := range cronDFiles {
		hash, _ := hashFileContent(path)
		key := fmt.Sprintf("_crond:%s", filepath.Base(path))
		prev, exists := store.GetRaw(key)
		if exists && prev != hash {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "crond_change",
				Message:  fmt.Sprintf("Cron.d file modified: %s", path),
			})
		}
		store.SetRaw(key, hash)
	}

	return findings
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
