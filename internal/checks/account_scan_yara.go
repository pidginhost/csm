package checks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/yara"
)

// checkAccountYARA is the YARA content pass of a full account scan. It walks
// the scoped account's document roots, the same roots the other content
// checks use, and sends one file at a time through the active backend: the
// isolated worker in production, which serves one request at a time. It
// keeps no cursor, cache or carry-forward state; an account scan only
// reports.
func checkAccountYARA(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	backend := activeYARABackend()
	if backend == nil || backend.RuleCount() == 0 {
		if !yaraAvailable() {
			return nil
		}
		return []alert.Finding{{
			Severity: alert.High,
			Check:    "yara_scan_incomplete",
			Message:  "YARA account scan could not start because no compiled rules are available",
		}}
	}
	maxBytes := scanMaxFileBytes(ctx)
	if maxBytes <= 0 {
		maxBytes = FullScanMaxFileBytes(cfg)
	}
	respectIgnores := scanRespectsIgnores(ctx, cfg)

	// Stop with the margin left so the partial result is returned: the
	// account scan drops every finding of a check that overruns its budget.
	var softDeadline time.Time
	if deadline, ok := ctx.Deadline(); ok {
		softDeadline = deadline.Add(-yaraDeepDeadlineMargin)
	}
	gaps := newYARAGapCollector()
	// The report only names gaps; nothing is carried forward by alias.
	gaps.resolveAliases = func(string) ([]string, bool) { return nil, true }
	var findings []alert.Finding
	stopped := false
	stop := func(path string) bool {
		if stopped || ctx.Err() != nil {
			return true
		}
		if !softDeadline.IsZero() && !yaraDeepNow().Before(softDeadline) {
			stopped = true
			gaps.recordUnknownRange(fmt.Sprintf("stopped at %s before the time budget ran out", path))
		}
		return stopped
	}

	var walk func(dir string)
	walk = func(dir string) {
		entries, err := osFS.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				gaps.recordUnknownRange(fmt.Sprintf("reading %s: %v", dir, err))
			}
			return
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			if stop(path) {
				return
			}
			if respectIgnores && ignoredPath(cfg, path) {
				continue
			}
			// A symlink is neither entered nor scanned: its target is not
			// necessarily the account's and may be anywhere on the host.
			switch {
			case entry.IsDir():
				walk(path)
			case entry.Type().IsRegular():
				findings = append(findings, scanAccountYARAFile(backend, gaps, path, entry, maxBytes)...)
			}
		}
	}

	homes, err := GetScanHomeDirs(ctx)
	if err != nil {
		gaps.recordUnknownRange(fmt.Sprintf("resolving the account home: %v", err))
	}
	for _, home := range homes {
		for _, root := range accountDocRoots(scanHomeDirPath(home)) {
			if stop(root) {
				break
			}
			info, err := osFS.Lstat(root)
			switch {
			case err != nil:
				if !os.IsNotExist(err) {
					gaps.recordUnknownRange(fmt.Sprintf("inspecting %s: %v", root, err))
				}
				continue
			case info.Mode()&os.ModeSymlink != 0:
				gaps.recordUnknownRange(fmt.Sprintf("%s is a symbolic link and was not followed", root))
				continue
			case !info.IsDir():
				continue
			}
			walk(root)
		}
	}
	if !gaps.empty() {
		findings = append(findings, gaps.finding())
	}
	return findings
}

// scanAccountYARAFile sends one regular file through the backend. The size
// check comes first so a large media file or dump is never read at all.
func scanAccountYARAFile(backend yara.Backend, gaps *yaraGapCollector, path string, entry os.DirEntry, maxBytes int64) []alert.Finding {
	info, err := entry.Info()
	if err != nil {
		if !os.IsNotExist(err) {
			gaps.record(path, "stat_error")
		}
		return nil
	}
	if info.Size() == 0 {
		return nil
	}
	if info.Size() > maxBytes {
		gaps.record(path, "oversize")
		return nil
	}
	data, truncated, err := readRegularFileHead(path, maxBytes)
	if err != nil {
		if !os.IsNotExist(err) {
			gaps.record(path, "read_error")
		}
		return nil
	}
	if truncated {
		gaps.record(path, "oversize")
		return nil
	}
	// #nosec G115 -- maxBytes is FullScanMaxFileBytes or the job's copy of it, capped far below MaxInt.
	matches, contentSHA256, err := yara.ScanContentOrPathChecked(backend, path, data, int(maxBytes))
	if err != nil {
		gaps.record(path, "scan_error")
		return nil
	}
	if len(matches) == 0 {
		return nil
	}
	if contentSHA256 == "" {
		contentSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	findings := make([]alert.Finding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, alert.Finding{
			Severity:      yaraMatchSeverity(match.Meta["severity"]),
			Check:         "yara_match_scheduled",
			Message:       fmt.Sprintf("YARA rule match [%s]: %s", match.RuleName, path),
			Details:       fmt.Sprintf("Full account scan matched YARA rule %s", match.RuleName) + signatures.ReferencedPayloadDetail(data),
			FilePath:      path,
			ContentSHA256: contentSHA256,
			DetectLogic:   ContentDetectionVersion(),
		})
	}
	return findings
}

// ignoredPath reports whether path matches the operator's ignore_paths.
func ignoredPath(cfg *config.Config, path string) bool {
	for _, ignore := range cfg.Suppressions.IgnorePaths {
		if matchGlob(path, ignore) {
			return true
		}
	}
	return false
}
