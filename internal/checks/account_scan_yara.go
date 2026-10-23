package checks

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/safepath"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
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

	// Leave time for the last worker call. Completed detections are also
	// checkpointed in case that call or filesystem I/O exceeds the margin.
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
		if stopped {
			return true
		}
		if ctx.Err() != nil || (!softDeadline.IsZero() && !yaraDeepNow().Before(softDeadline)) {
			stopped = true
			gaps.recordUnknownRange(fmt.Sprintf("stopped at %s before the time budget ran out", path))
		}
		return stopped
	}

	var walk func(dir string, pinned *safepath.Dir)
	walk = func(dir string, pinned *safepath.Dir) {
		defer func() { _ = pinned.Close() }()
		entries, err := pinned.ReadDir()
		if err != nil {
			gaps.recordUnknownRange(fmt.Sprintf("reading %s: %v", dir, err))
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
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
				child, err := pinned.Walk(entry.Name())
				if err != nil {
					gaps.recordUnknownRange(fmt.Sprintf("opening %s: %v", path, err))
					continue
				}
				walk(path, child)
			case entry.Type().IsRegular():
				matches := scanAccountYARAFile(backend, gaps, pinned, path, maxBytes, cfg.StatePath)
				findings = append(findings, matches...)
				publishAccountScanFindings(ctx, matches)
			}
		}
	}

	scanHome := func(homePath string) {
		if stop(homePath) {
			return
		}
		pinned, err := openAccountYARAHome(homePath)
		if err != nil {
			gaps.recordUnknownRange(fmt.Sprintf("opening %s: %v", homePath, err))
			return
		}
		defer func() { _ = pinned.Close() }()
		entries, err := pinned.ReadDir()
		if err != nil {
			gaps.recordUnknownRange(fmt.Sprintf("reading %s: %v", homePath, err))
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if !accountContentDir(entry.Name()) {
				continue
			}
			root := filepath.Join(homePath, entry.Name())
			if stop(root) {
				break
			}
			if respectIgnores && ignoredPath(cfg, root) {
				continue
			}
			switch {
			case entry.Type()&os.ModeSymlink != 0:
				if entry.Name() == "public_html" {
					gaps.recordUnknownRange(fmt.Sprintf("%s is a symbolic link and was not followed", root))
				}
				continue
			case !entry.IsDir():
				continue
			}
			child, err := pinned.Walk(entry.Name())
			if err != nil {
				gaps.recordUnknownRange(fmt.Sprintf("opening %s: %v", root, err))
				continue
			}
			walk(root, child)
		}
	}
	homes, err := GetScanHomeDirs(ctx)
	if err != nil {
		gaps.recordUnknownRange(fmt.Sprintf("resolving the account home: %v", err))
	}
	for _, home := range homes {
		scanHome(scanHomeDirPath(home))
	}
	if !gaps.empty() {
		findings = append(findings, gaps.finding())
	}
	return findings
}

func openAccountYARAHome(home string) (*safepath.Dir, error) {
	// The platform's account-root parent is operator controlled. Pin the
	// volume and account components below it so neither can redirect reads.
	volume := filepath.Dir(home)
	anchor, err := safepath.OpenDir(filepath.Dir(volume))
	if err != nil {
		return nil, err
	}
	defer func() { _ = anchor.Close() }()
	return anchor.Walk(filepath.Join(filepath.Base(volume), filepath.Base(home)))
}

// scanAccountYARAFile sends one regular file through the backend. The size
// check comes first so a large media file or dump is never read at all.
func scanAccountYARAFile(backend yara.Backend, gaps *yaraGapCollector, dir *safepath.Dir, path string, maxBytes int64, statePath string) []alert.Finding {
	file, err := dir.OpenFile(filepath.Base(path), os.O_RDONLY, 0)
	if err != nil {
		gaps.record(path, "read_error")
		return nil
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		gaps.record(path, "stat_error")
		return nil
	}
	if info.Size() > maxBytes {
		gaps.record(path, "oversize")
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes))
	if err != nil {
		gaps.record(path, "read_error")
		return nil
	}
	after, err := file.Stat()
	if err != nil || !sameFileSnapshot(info, after) || int64(len(data)) != info.Size() {
		gaps.record(path, "changed")
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	matches, err := scanAccountYARASnapshot(backend, path, data, statePath)
	if err != nil {
		gaps.record(path, "scan_error")
		return nil
	}
	if len(matches) == 0 {
		return nil
	}
	contentSHA256 := fmt.Sprintf("%x", sha256.Sum256(data))
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

func scanAccountYARASnapshot(backend yara.Backend, path string, data []byte, statePath string) ([]yara.Match, error) {
	matches, err := yara.ScanBytesChecked(backend, path, data)
	if !errors.Is(err, yaraipc.ErrPayloadTooLarge) {
		return matches, err
	}
	// The worker cannot receive large snapshots inline. A private copy keeps
	// its retry bound to these bytes even if the tenant replaces the source.
	// Keep it with daemon state, outside the monitored account and temp trees.
	snapshot, err := os.CreateTemp(statePath, "account-yara-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(snapshot.Name()) }()
	defer func() { _ = snapshot.Close() }()
	if _, writeErr := snapshot.Write(data); writeErr != nil {
		return nil, writeErr
	}
	result, err := yara.ScanFileChecked(backend, snapshot.Name(), len(data))
	if err != nil {
		return nil, err
	}
	if result.ContentSHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) {
		return nil, errFileChanged
	}
	return result.Matches, nil
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
