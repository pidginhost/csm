package checks

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/state"
)

// crontabBase64Truncated counts base64 candidates that hit
// crontabBase64BlobMaxBytes. Sustained growth means an attacker is
// padding outer blobs to push the real payload past the decode window;
// raise the cap or split the scanner.
var (
	crontabBase64Truncated     *metrics.Counter
	crontabBase64TruncatedOnce sync.Once
)

func observeCrontabBase64Truncation() {
	crontabBase64TruncatedOnce.Do(func() {
		crontabBase64Truncated = metrics.NewCounter(
			"csm_checks_crontab_base64_truncated_total",
			"Crontab base64 candidates that exceeded the per-blob decode cap before decoded-content pattern matching ran. Sustained growth means the scanner inspected only the leading decoded window of large encoded cron content.",
		)
		metrics.MustRegister("csm_checks_crontab_base64_truncated_total", crontabBase64Truncated)
	})
	crontabBase64Truncated.Inc()
}

func CheckCrontabs(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}
	var findings []alert.Finding

	// Rank by mtime desc so recently-touched crontabs process first
	// when the check timeout cuts iteration short. The /var/spool/cron
	// list is small on most hosts; the rank cost is negligible and the
	// fairness invariant matches the rest of the per-account scanners.
	if ctx.Err() != nil {
		return findings
	}
	crontabs, _ := osFS.Glob("/var/spool/cron/*")
	rankedCrontabs := rankPathsByMtimeDesc(ctx, crontabs, effectiveAccountScanMaxFiles(cfg))
	if ctx.Err() != nil {
		return findings
	}
	for _, path := range rankedCrontabs {
		if ctx.Err() != nil {
			return findings
		}
		user := filepath.Base(path)
		if user == "root" {
			// Track root crontab changes via hash
			hash, err := hashFileContent(path)
			if err != nil {
				continue
			}
			if ctx.Err() != nil {
				return findings
			}
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
		if ctx.Err() != nil {
			return findings
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
	if ctx.Err() != nil {
		return findings
	}
	cronDFiles, _ := osFS.Glob("/etc/cron.d/*")
	rankedCronDFiles := rankPathsByMtimeDesc(ctx, cronDFiles, effectiveAccountScanMaxFiles(cfg))
	if ctx.Err() != nil {
		return findings
	}
	for _, path := range rankedCronDFiles {
		if ctx.Err() != nil {
			return findings
		}
		hash, err := hashFileContent(path)
		if err != nil {
			continue
		}
		if ctx.Err() != nil {
			return findings
		}
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
// 16384 encoded bytes -> ~12KB decoded; comfortably fits any realistic cron
// payload while bounding work on adversarial input. An attacker padding
// past this cap is metered via csm_checks_crontab_base64_truncated_total
// so operators can spot and raise it.
//
// Must stay a multiple of 4 -- standard base64 needs aligned input or
// DecodeString errors and the candidate is silently skipped.
const crontabBase64BlobMaxBytes = 16384

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
			observeCrontabBase64Truncation()
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
