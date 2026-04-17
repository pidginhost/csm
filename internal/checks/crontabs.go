package checks

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func CheckCrontabs(ctx context.Context, _ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

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
		for _, pattern := range MatchCrontabPatternsDeep(content) {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "suspicious_crontab",
				Message:  fmt.Sprintf("Suspicious pattern in crontab for user %s: %s", user, pattern),
				Details:  fmt.Sprintf("File: %s\nContent:\n%s", path, truncate(content, 500)),
			})
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

// crontabSuspiciousPatterns is the shared allowlist of case-insensitive
// substrings that mark a crontab line as likely malicious. Single source of
// truth for CheckCrontabs (system scan) and makeAccountCrontabCheck
// (per-account scan) so the two cannot drift apart.
var crontabSuspiciousPatterns = []string{
	"defunct-kernel",
	"SEED PRNG",
	"base64_decode",
	"base64 -d|bash",
	"base64 -d | bash",
	"base64 --decode|bash",
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

// matchCrontabPatterns returns patterns from crontabSuspiciousPatterns that
// appear as case-insensitive substrings of content, preserving list order.
func matchCrontabPatterns(content string) []string {
	lower := strings.ToLower(content)
	var matched []string
	for _, pattern := range crontabSuspiciousPatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			matched = append(matched, pattern)
		}
	}
	return matched
}

// crontabBase64BlobMaxBytes caps a single base64 candidate before decoding.
// 8192 encoded bytes -> ~6KB decoded; comfortably fits any realistic cron
// payload while bounding work on adversarial input.
const crontabBase64BlobMaxBytes = 8192

// crontabBase64BlobMaxCount caps the number of base64 candidates examined
// per crontab. A realistic gsocket cron entry has one outer blob; we
// allow enough headroom for a handful without doing unbounded work.
const crontabBase64BlobMaxCount = 16

// crontabBase64BlobRE matches contiguous standard-alphabet base64 of
// length >= 40 (with optional padding). The 40-char floor avoids matching
// short config IDs and noise like Wordfence cookie names.
var crontabBase64BlobRE = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)

// MatchCrontabPatternsDeep is matchCrontabPatterns plus a single base64
// decode pass: it pulls out base64 candidates from content and re-runs
// pattern matching on the decoded bytes. Catches attackers who wrap the
// `base64 -d|bash` pipe chain in an outer base64 layer so the literal
// markers never appear in the cron file as written. Single decode depth;
// no recursion.
func MatchCrontabPatternsDeep(content string) []string {
	matched := matchCrontabPatterns(content)
	seen := make(map[string]bool, len(matched))
	for _, m := range matched {
		seen[m] = true
	}
	candidates := crontabBase64BlobRE.FindAllString(content, crontabBase64BlobMaxCount)
	for _, blob := range candidates {
		if len(blob) > crontabBase64BlobMaxBytes {
			blob = blob[:crontabBase64BlobMaxBytes]
		}
		decoded, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			continue
		}
		for _, m := range matchCrontabPatterns(string(decoded)) {
			if !seen[m] {
				matched = append(matched, m)
				seen[m] = true
			}
		}
	}
	return matched
}
