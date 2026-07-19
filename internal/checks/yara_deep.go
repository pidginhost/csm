package checks

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

var activeYARABackend = yara.Active
var yaraAvailable = yara.Available

// yaraDeepScanMu serializes the persisted host-wide cursor. Manual baseline
// scans can overlap the daemon's scheduled scan; without serialization, the
// older window can overwrite a newer cursor after it returns.
var yaraDeepScanMu sync.Mutex

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

type yaraDeepScanEntry struct {
	path      string
	sortKey   string
	info      os.FileInfo
	err       error
	inspected bool
}

type yaraDeepScanHeap []yaraDeepScanEntry

func (h yaraDeepScanHeap) Len() int           { return len(h) }
func (h yaraDeepScanHeap) Less(i, j int) bool { return h[i].sortKey < h[j].sortKey }
func (h yaraDeepScanHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *yaraDeepScanHeap) Push(value any)    { *h = append(*h, value.(yaraDeepScanEntry)) }
func (h *yaraDeepScanHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	old[last] = yaraDeepScanEntry{}
	*h = old[:last]
	return value
}

func CheckYARADeep(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	yaraDeepScanMu.Lock()
	defer yaraDeepScanMu.Unlock()

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
	lastScanned := resume
	sep := string(filepath.Separator)
	subtreePrefix := func(path string) string {
		path = filepath.Clean(path)
		if strings.HasSuffix(path, sep) {
			return path
		}
		return path + sep
	}
	advanceCursor := func(path string) {
		if path > lastScanned {
			lastScanned = path
		}
	}

	// subtreeCovered reports whether every path under dir sorts before the
	// resume point. Children all share the dir+sep prefix, so when resume
	// does not itself start with that prefix, any child compares to resume
	// exactly as the prefix does. Comparing the bare dir path instead would
	// wrongly skip siblings like "ab/" when the cursor sits at "ab.zz"
	// ('/' sorts after '.'). An exact prefix cursor records a subtree already
	// accounted for this cycle, including an empty or unreadable directory.
	subtreeCovered := func(dir string) bool {
		prefix := subtreePrefix(dir)
		return resume != "" && (resume == prefix || (!strings.HasPrefix(resume, prefix) && prefix < resume))
	}

	var scanDir func(string)
	scanDir = func(dir string) {
		if ctx.Err() != nil || stoppedEarly {
			return
		}
		if outOfTime() {
			stoppedEarly = true
			return
		}
		entries, err := osFS.ReadDir(dir)
		if err != nil {
			incomplete++
			if firstIncomplete == "" {
				firstIncomplete = fmt.Sprintf("reading %s: %v", dir, err)
			}
			advanceCursor(subtreePrefix(dir))
			return
		}
		// A directory's candidate paths start at dir+separator, not at the
		// bare directory name. Bare-name order visits ab/ before ab.zz even
		// though every child under ab/ sorts after ab.zz. The heap starts
		// with each bare path as a lower bound, then requeues directories
		// under their path+separator key after Lstat reveals their type.
		ordered := make(yaraDeepScanHeap, len(entries))
		for i, entry := range entries {
			ordered[i].path = filepath.Join(dir, entry.Name())
			ordered[i].sortKey = ordered[i].path
		}
		heap.Init(&ordered)

		for ordered.Len() > 0 {
			if ctx.Err() != nil || stoppedEarly {
				return
			}
			if outOfTime() {
				stoppedEarly = true
				return
			}

			item := heap.Pop(&ordered).(yaraDeepScanEntry)
			if !item.inspected {
				item.info, item.err = osFS.Lstat(item.path)
				item.inspected = true
			}
			path := item.path

			if item.err == nil && item.info.Mode()&os.ModeSymlink == 0 && item.info.IsDir() {
				if item.sortKey == path {
					item.sortKey = subtreePrefix(path)
					heap.Push(&ordered, item)
					continue
				}
				if subtreeCovered(path) {
					continue
				}
				if outOfTime() {
					stoppedEarly = true
					return
				}
				scanDir(path)
				if ctx.Err() == nil && !stoppedEarly {
					advanceCursor(item.sortKey)
				}
				continue
			}

			if resume != "" && path <= resume {
				continue
			}
			if item.err != nil {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("inspecting %s: %v", path, item.err)
				}
				advanceCursor(path)
				continue
			}
			info := item.info
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() == 0 {
				advanceCursor(path)
				continue
			}
			if info.Size() > maxBytes {
				// Oversize files are intentionally not opened, but they still
				// count as covered progress for this rolling cycle.
				advanceCursor(path)
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("%s exceeds the %d-byte scan limit", path, maxBytes)
				}
				continue
			}
			if outOfTime() {
				stoppedEarly = true
				return
			}
			// Advance before opening so permanently unreadable or unscannable
			// files cannot wedge the cursor in place.
			advanceCursor(path)

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
			fingerprint := sha256.Sum256(data)
			contentSHA256 := fmt.Sprintf("%x", fingerprint)
			matches, scanErr := yara.ScanBytesChecked(backend, data)
			if errors.Is(scanErr, yaraipc.ErrPayloadTooLarge) {
				// Within the deep-scan size budget but too large for one inline
				// IPC frame once JSON base64 expands it. Scan by path instead of
				// recording a coverage gap an attacker could hide a payload
				// behind by padding it past the inline ceiling. The too-large
				// error is a client-side pre-check. The checked path scan still
				// reports a worker failure instead of treating it as clean.
				// #nosec G115 -- maxBytes is FullScanMaxFileBytes (int) widened to int64; the round-trip back to int is lossless.
				var pathResult yara.FileScanResult
				pathResult, scanErr = yara.ScanFileChecked(backend, path, int(maxBytes))
				if scanErr == nil {
					matches = pathResult.Matches
					contentSHA256 = pathResult.ContentSHA256
				}
			}
			if scanErr != nil {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("scanning %s: %v", path, scanErr)
				}
				continue
			}
			for _, match := range matches {
				finding := alert.Finding{
					Severity:      yaraMatchSeverity(match.Meta["severity"]),
					Check:         "yara_match_scheduled",
					Message:       fmt.Sprintf("YARA rule match [%s]: %s", match.RuleName, path),
					Details:       fmt.Sprintf("Scheduled deep scan matched YARA rule %s", match.RuleName),
					FilePath:      path,
					ContentSHA256: contentSHA256,
					DetectLogic:   ContentDetectionVersion(),
				}
				findings = append(findings, finding)
			}
		}
	}

	roots := ResolveWebRoots(cfg)
	normalizedRoots := roots[:0]
	seenRoots := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		root = filepath.Clean(root)
		if _, exists := seenRoots[root]; exists {
			continue
		}
		seenRoots[root] = struct{}{}
		normalizedRoots = append(normalizedRoots, root)
	}
	roots = normalizedRoots
	sort.Slice(roots, func(i, j int) bool { return subtreePrefix(roots[i]) < subtreePrefix(roots[j]) })
	for _, root := range roots {
		if ctx.Err() != nil || stoppedEarly {
			break
		}
		if outOfTime() {
			stoppedEarly = true
			break
		}
		if subtreeCovered(root) {
			continue
		}
		scanDir(root)
		if ctx.Err() == nil && !stoppedEarly {
			advanceCursor(subtreePrefix(root))
		}
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
			next.LastFullCycleTS = cur.LastFullCycleTS
			next.WrappedAt = cur.WrappedAt
			if next.WrappedAt.IsZero() {
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
	if stoppedEarly && !cur.WrappedAt.IsZero() && now.Sub(cur.WrappedAt) > yaraDeepFullCycleStale {
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
