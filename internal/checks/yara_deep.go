package checks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/yara"
)

var activeYARABackend = yara.Active
var yaraAvailable = yara.Available

// yaraDeepNow is indirected so tests can drive the soft-deadline clock.
var yaraDeepNow = time.Now

// yaraDeepDeadlineMargin is how much of the runner budget the walk leaves
// unused so a partial run returns its findings before the context deadline.
// A check that overruns its budget gets every returned finding dropped by
// the runner, so stopping early is the only way partial coverage survives.
const yaraDeepDeadlineMargin = 45 * time.Second

// yaraDeepFullCycleStale bounds how long rolling coverage may go without
// completing a full pass before the check surfaces a warning.
const yaraDeepFullCycleStale = 30 * 24 * time.Hour

// yaraDeepCursorCheck is the host-scope scan-cursor key (account "") under
// which the rolling deep-scan records its progress.
const yaraDeepCursorCheck = "yara_deep"

func CheckYARADeep(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	backend := activeYARABackend()
	if backend == nil || backend.RuleCount() == 0 {
		markCheckIncomplete(ctx, "yara_deep")
		if yaraAvailable() {
			return []alert.Finding{{
				Severity: alert.High,
				Check:    "yara_scan_incomplete",
				Message:  "YARA deep scan could not start because no compiled rules are available",
			}}
		}
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	maxBytes := int64(FullScanMaxFileBytes(cfg))

	db := store.Global()
	var cur store.ScanCursorRecord
	if db != nil {
		rec, ok, err := db.GetScanCursor("", yaraDeepCursorCheck)
		if err != nil {
			fmt.Fprintf(os.Stderr, "yara_deep: cursor read: %v\n", err)
		} else if ok {
			cur = rec
		}
	}
	resume := cur.LastPath

	var softDeadline time.Time
	if deadline, ok := ctx.Deadline(); ok {
		softDeadline = deadline.Add(-yaraDeepDeadlineMargin)
	}
	outOfTime := func() bool {
		return !softDeadline.IsZero() && !yaraDeepNow().Before(softDeadline)
	}

	var findings []alert.Finding
	var incomplete int
	var firstIncomplete string
	stoppedEarly := false
	lastScanned := ""
	sep := string(filepath.Separator)

	// subtreeCovered reports whether every path under dir sorts before the
	// resume point. Children all share the dir+sep prefix, so when resume
	// does not itself start with that prefix, any child compares to resume
	// exactly as the prefix does. Comparing the bare dir path instead would
	// wrongly skip siblings like "ab/" when the cursor sits at "ab.zz"
	// ('/' sorts after '.').
	subtreeCovered := func(dir string) bool {
		return resume != "" && !strings.HasPrefix(resume, dir+sep) && dir+sep < resume
	}

	var scanDir func(string)
	scanDir = func(dir string) {
		if ctx.Err() != nil || stoppedEarly {
			return
		}
		entries, err := osFS.ReadDir(dir)
		if err != nil {
			incomplete++
			if firstIncomplete == "" {
				firstIncomplete = fmt.Sprintf("reading %s: %v", dir, err)
			}
			return
		}
		// The cursor's resume comparisons assume one stable path order
		// across runs; sort defensively rather than trusting the injector.
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if ctx.Err() != nil || stoppedEarly {
				return
			}
			path := filepath.Join(dir, entry.Name())
			info, err := osFS.Lstat(path)
			if err != nil {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("inspecting %s: %v", path, err)
				}
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if info.IsDir() {
				if subtreeCovered(path) {
					continue
				}
				scanDir(path)
				continue
			}
			if !info.Mode().IsRegular() || info.Size() == 0 {
				continue
			}
			if resume != "" && path <= resume {
				continue
			}
			if outOfTime() {
				stoppedEarly = true
				return
			}
			// Advance past error and oversize files too, so a permanently
			// unreadable file cannot wedge the cursor in place.
			lastScanned = path
			if info.Size() > maxBytes {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("%s exceeds the %d-byte scan limit", path, maxBytes)
				}
				continue
			}

			file, err := osFS.Open(path)
			if err != nil {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("opening %s: %v", path, err)
				}
				continue
			}
			openedInfo, statErr := file.Stat()
			if statErr != nil || !openedInfo.Mode().IsRegular() || openedInfo.Size() > maxBytes {
				_ = file.Close()
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("%s changed while it was being opened", path)
				}
				continue
			}
			data, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || int64(len(data)) > maxBytes {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("reading %s failed or exceeded the scan limit", path)
				}
				continue
			}
			matches, scanErr := yara.ScanBytesChecked(backend, data)
			if scanErr != nil {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("scanning %s: %v", path, scanErr)
				}
				continue
			}
			fingerprint := sha256.Sum256(data)
			for _, match := range matches {
				finding := alert.Finding{
					Severity:      yaraMatchSeverity(match.Meta["severity"]),
					Check:         "yara_match_scheduled",
					Message:       fmt.Sprintf("YARA rule match [%s]: %s", match.RuleName, path),
					Details:       fmt.Sprintf("Scheduled deep scan matched YARA rule %s", match.RuleName),
					FilePath:      path,
					ContentSHA256: fmt.Sprintf("%x", fingerprint),
					DetectLogic:   ContentDetectionVersion(),
				}
				findings = append(findings, finding)
			}
		}
	}

	roots := ResolveWebRoots(cfg)
	sort.Strings(roots)
	for _, root := range roots {
		if ctx.Err() != nil || stoppedEarly {
			break
		}
		if subtreeCovered(root) {
			continue
		}
		scanDir(root)
	}
	if ctx.Err() != nil {
		// The runner drops every finding a check returns after its budget
		// expired, so there is nothing worth reporting; leave the cursor
		// untouched and let the next run redo this window.
		return nil
	}

	now := yaraDeepNow().UTC()
	if db != nil {
		var next store.ScanCursorRecord
		next.Check = yaraDeepCursorCheck
		if stoppedEarly {
			next.LastPath = lastScanned
			if next.LastPath == "" {
				next.LastPath = resume
			}
			next.LastFullCycleTS = cur.LastFullCycleTS
			next.WrappedAt = cur.WrappedAt
			if resume == "" || next.WrappedAt.IsZero() {
				next.WrappedAt = now
			}
		} else {
			next.LastFullCycleTS = now
		}
		if err := db.PutScanCursor(next); err != nil {
			fmt.Fprintf(os.Stderr, "yara_deep: cursor write: %v\n", err)
		}
	}

	// A run that resumed mid-cycle or stopped at the soft deadline saw only
	// a window of the space; completing it would purge findings discovered
	// by the other windows of this cycle.
	if stoppedEarly || resume != "" {
		markCheckIncomplete(ctx, "yara_deep")
	}
	if stoppedEarly && resume != "" && !cur.WrappedAt.IsZero() && now.Sub(cur.WrappedAt) > yaraDeepFullCycleStale {
		findings = append(findings, alert.Finding{
			Severity: alert.Warning,
			Check:    "yara_scan_incomplete",
			Message:  fmt.Sprintf("Rolling YARA deep scan has not completed a full pass since %s", cur.WrappedAt.Format("2006-01-02")),
			Details:  "Each run advances the cursor inside its time budget; a pass this stale means the budget is too small for the content volume.",
		})
	}
	if incomplete > 0 {
		markCheckIncomplete(ctx, "yara_deep")
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "yara_scan_incomplete",
			Message:  fmt.Sprintf("YARA deep scan could not inspect %d file or directory entries", incomplete),
			Details:  firstIncomplete,
		})
	}
	return findings
}

func yaraMatchSeverity(value string) alert.Severity {
	switch strings.ToLower(value) {
	case "warning", "low", "medium":
		return alert.Warning
	case "high":
		return alert.High
	default:
		return alert.Critical
	}
}
