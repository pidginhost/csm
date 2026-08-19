package checks

import (
	"container/heap"
	"context"
	"crypto/sha256"
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
	"github.com/pidginhost/csm/internal/jstaint"
	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/yara"
)

var activeYARABackend = yara.Active
var yaraAvailable = yara.Available

// yaraDeepScanMu serializes the persisted host-wide cursors. Manual baseline
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
// which the rolling deep-scan records the YARA consumer's progress.
const yaraDeepCursorCheck = "yara_deep"

// deepScanConsumer is one consumer of the shared ordered deep-content walk.
// Each consumer resumes from its own persisted cursor and advances it
// independently, so a missing backend cannot stall another analyzer's
// coverage and one analyzer's gap cannot move another's resume point.
type deepScanConsumer struct {
	name        string
	dispatch    bool
	resume      string
	lastScanned string
	cur         store.ScanCursorRecord
}

// wants reports whether this consumer still needs the given path this cycle.
func (c *deepScanConsumer) wants(path string) bool {
	return c.dispatch && (c.resume == "" || path > c.resume)
}

// advance is monotonic-max: a leading consumer keeps its resume point while
// the lagging one catches up over the shared walk.
func (c *deepScanConsumer) advance(path string) {
	if c.dispatch && path > c.lastScanned {
		c.lastScanned = path
	}
}

// resetDeepScanCursor clears a disabled consumer's persisted cursor so
// re-enabling it starts a full cycle instead of resuming a stale window.
func resetDeepScanCursor(db *store.DB, check string) {
	if db == nil {
		return
	}
	rec, ok, err := db.GetScanCursor("", check)
	if err != nil || !ok {
		return
	}
	if rec.LastPath == "" && rec.WrappedAt.IsZero() && rec.LastFullCycleTS.IsZero() {
		return
	}
	var next store.ScanCursorRecord
	next.Check = check
	if err := db.PutScanCursor(next); err != nil {
		fmt.Fprintf(os.Stderr, "%s: cursor reset: %v\n", check, err)
	}
}

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

// CheckYARADeep is the shared rolling deep-content walk. It reads each file
// once and dispatches the same in-memory snapshot to three consumers with
// independent cursors and completion records: the YARA backend and the JS and
// PHP taint analyzers. A missing, disabled, or failed consumer neither prevents
// nor controls another consumer's progress.
func CheckYARADeep(ctx context.Context, cfg *config.Config, st *state.Store) []alert.Finding {
	yaraDeepScanMu.Lock()
	defer yaraDeepScanMu.Unlock()
	if ctx.Err() != nil {
		return nil
	}

	db := store.Global()
	yaraConsumer := &deepScanConsumer{name: yaraDeepCursorCheck}
	jsConsumer := &deepScanConsumer{name: jsTaintDeepCursorCheck}
	phpConsumer := &deepScanConsumer{name: phpTaintDeepCursorCheck}
	consumers := []*deepScanConsumer{yaraConsumer, jsConsumer, phpConsumer}

	yaraOff := yaraDeepConsumerDisabled(cfg)
	jsOff := jsTaintDeepConsumerDisabled(cfg)
	jsConsumer.dispatch = !jsOff
	phpOff := phpTaintDeepConsumerDisabled(cfg)
	phpReady := phpTaintAnalyzerReady()
	// An absent isolated analyzer is not a coverage gap: it means the feature
	// is not active on this host. Dispatching anyway would record every
	// candidate as unexamined on every scan.
	phpConsumer.dispatch = !phpOff && phpReady
	if !phpOff && !phpReady {
		// Keep prior state while the feature is inactive. Treating an inactive
		// owner as completed would purge findings without examining their files.
		markCheckIncomplete(ctx, logicalOwnerPHPTaintDeep)
	}
	// Disabled-consumer resets are persistent scan progress too. Commit them
	// only on a normal return path so a hard-canceled shared walk writes no
	// cursor state for any consumer.
	resetDisabledCursors := func() {
		if yaraOff {
			resetDeepScanCursor(db, yaraDeepCursorCheck)
		}
		if jsOff {
			resetDeepScanCursor(db, jsTaintDeepCursorCheck)
		}
		if phpOff {
			resetDeepScanCursor(db, phpTaintDeepCursorCheck)
		}
	}

	var findings []alert.Finding
	backend := activeYARABackend()
	yaraReady := backend != nil && backend.RuleCount() > 0
	yaraConsumer.dispatch = !yaraOff && yaraReady
	if !yaraOff && !yaraReady {
		// A missing backend is a YARA coverage gap, never a JS one: mark only
		// the YARA owner incomplete and leave its cursor unchanged so it can
		// neither purge nor skip its own unscanned range, while the JS pass
		// below still covers its cycle.
		markCheckIncomplete(ctx, "yara_deep")
		if yaraAvailable() {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "yara_scan_incomplete",
				Message:  "YARA deep scan could not start because no compiled rules are available",
			})
		}
	}
	if !yaraConsumer.dispatch && !jsConsumer.dispatch && !phpConsumer.dispatch {
		if ctx.Err() != nil {
			return nil
		}
		resetDisabledCursors()
		return findings
	}
	maxBytes := int64(FullScanMaxFileBytes(cfg))
	jsMaxBytes := int64(jstaint.MaxSourceBytes)
	phpMaxBytes := int64(phptaint.MaxSourceBytes)

	for _, c := range consumers {
		if !c.dispatch || db == nil {
			continue
		}
		rec, ok, err := db.GetScanCursor("", c.name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: cursor read: %v\n", c.name, err)
		} else if ok {
			c.cur = rec
		}
		c.resume = c.cur.LastPath
		c.lastScanned = c.resume
	}

	// The shared walk starts at the earliest dispatchable resume point; a
	// consumer whose cursor is ahead skips already-covered paths via wants()
	// while the lagging consumer catches up on the same snapshot reads.
	walkResume := ""
	firstResume := true
	for _, c := range consumers {
		if !c.dispatch {
			continue
		}
		if firstResume || c.resume < walkResume {
			walkResume = c.resume
			firstResume = false
		}
	}

	var softDeadline time.Time
	if deadline, ok := ctx.Deadline(); ok {
		softDeadline = deadline.Add(-yaraDeepDeadlineMargin)
	}
	outOfTime := func() bool {
		return !softDeadline.IsZero() && !yaraDeepNow().Before(softDeadline)
	}

	var incomplete int
	var firstIncomplete string
	jsGaps := newJSTaintGapCollector()
	phpGaps := newPHPTaintGapCollector()
	// Set when a walk error makes the unscanned range unknowable (a failed
	// Lstat may hide a directory). Shared by every path-based consumer,
	// because none of them can bound what they missed after one.
	unknownRangeGap := false
	stoppedEarly := false
	sep := string(filepath.Separator)
	subtreePrefix := func(path string) string {
		path = filepath.Clean(path)
		if strings.HasSuffix(path, sep) {
			return path
		}
		return path + sep
	}
	advanceAll := func(path string) {
		for _, c := range consumers {
			c.advance(path)
		}
	}

	// subtreeCovered reports whether every path under dir sorts before the
	// earliest resume point. Children all share the dir+sep prefix, so when
	// resume does not itself start with that prefix, any child compares to
	// resume exactly as the prefix does. Comparing the bare dir path instead
	// would wrongly skip siblings like "ab/" when the cursor sits at "ab.zz"
	// ('/' sorts after '.'). An exact prefix cursor records a subtree already
	// accounted for this cycle, including an empty or unreadable directory.
	subtreeCovered := func(dir string) bool {
		prefix := subtreePrefix(dir)
		return walkResume != "" && (walkResume == prefix || (!strings.HasPrefix(walkResume, prefix) && prefix < walkResume))
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
			// The affected paths are unknowable, so every dispatchable
			// consumer records the gap check-wide.
			if yaraConsumer.dispatch {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("reading %s: %v", dir, err)
				}
			}
			if jsConsumer.dispatch || phpConsumer.dispatch {
				unknownRangeGap = true
			}
			advanceAll(subtreePrefix(dir))
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
					advanceAll(item.sortKey)
				}
				continue
			}

			yaraWants := yaraConsumer.wants(path)
			jsWants := jsConsumer.wants(path)
			phpWants := phpConsumer.wants(path)
			if !yaraWants && !jsWants && !phpWants {
				continue
			}
			if item.err != nil {
				// A failed Lstat may hide a directory, so the gap range is
				// unknowable for either path-based carry-forward.
				if yaraWants {
					incomplete++
					if firstIncomplete == "" {
						firstIncomplete = fmt.Sprintf("inspecting %s: %v", path, item.err)
					}
				}
				if jsWants || phpWants {
					unknownRangeGap = true
				}
				advanceAll(path)
				continue
			}
			info := item.info
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() == 0 {
				advanceAll(path)
				continue
			}
			if yaraWants && info.Size() > maxBytes {
				// Oversize files are intentionally not opened, but they still
				// count as covered progress for this rolling cycle. The gap
				// advances only its own consumer: a soft-deadline stop right
				// after this gate must not move the other consumer past a
				// file it never received.
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("%s exceeds the %d-byte scan limit", path, maxBytes)
				}
				yaraConsumer.advance(path)
				yaraWants = false
			}
			if phpWants && info.Size() > phpMaxBytes {
				phpGaps.record(path, phptaint.StatusOversize.String())
				phpConsumer.advance(path)
				phpWants = false
			}
			if jsWants && info.Size() > jsMaxBytes {
				// Metadata alone decides the JS oversize gap; the bytes are
				// read below only if YARA still needs them.
				jsGaps.record(path, jstaint.StatusOversize.String())
				jsConsumer.advance(path)
				jsWants = false
			}
			if !yaraWants && !jsWants && !phpWants {
				continue
			}
			if outOfTime() {
				stoppedEarly = true
				return
			}
			// Advance before opening so permanently unreadable or unscannable
			// files cannot wedge the cursor in place.
			advanceAll(path)

			file, err := osFS.Open(path)
			if err != nil {
				if yaraWants {
					incomplete++
					if firstIncomplete == "" {
						firstIncomplete = fmt.Sprintf("opening %s: %v", path, err)
					}
				}
				if jsWants {
					jsGaps.record(path, "read_error")
				}
				if phpWants {
					phpGaps.record(path, "read_error")
				}
				continue
			}
			openedInfo, statErr := file.Stat()
			if statErr != nil || !openedInfo.Mode().IsRegular() {
				_ = file.Close()
				if yaraWants {
					incomplete++
					if firstIncomplete == "" {
						firstIncomplete = fmt.Sprintf("%s changed while it was being opened", path)
					}
				}
				if jsWants {
					jsGaps.record(path, "changed_during_read")
				}
				if phpWants {
					phpGaps.record(path, "changed_during_read")
				}
				continue
			}
			if yaraWants && openedInfo.Size() > maxBytes {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("%s changed while it was being opened", path)
				}
				yaraWants = false
			}
			if phpWants && openedInfo.Size() > phpMaxBytes {
				phpGaps.record(path, "changed_during_read")
				phpWants = false
			}
			if jsWants && openedInfo.Size() > jsMaxBytes {
				jsGaps.record(path, "changed_during_read")
				jsWants = false
			}
			if !yaraWants && !jsWants && !phpWants {
				_ = file.Close()
				continue
			}
			readCap := int64(0)
			if yaraWants {
				readCap = maxBytes
			}
			if jsWants && jsMaxBytes > readCap {
				readCap = jsMaxBytes
			}
			if phpWants && phpMaxBytes > readCap {
				readCap = phpMaxBytes
			}
			data, readErr := io.ReadAll(io.LimitReader(file, readCap+1))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || int64(len(data)) > readCap {
				if yaraWants {
					incomplete++
					if firstIncomplete == "" {
						firstIncomplete = fmt.Sprintf("reading %s failed or exceeded the scan limit", path)
					}
				}
				if jsWants {
					jsGaps.record(path, "read_error")
				}
				if phpWants {
					phpGaps.record(path, "read_error")
				}
				continue
			}
			if yaraWants && int64(len(data)) > maxBytes {
				incomplete++
				if firstIncomplete == "" {
					firstIncomplete = fmt.Sprintf("reading %s failed or exceeded the scan limit", path)
				}
				yaraWants = false
			}
			if phpWants && int64(len(data)) > phpMaxBytes {
				phpGaps.record(path, "changed_during_read")
				phpWants = false
			}
			if jsWants && int64(len(data)) > jsMaxBytes {
				jsGaps.record(path, "changed_during_read")
				jsWants = false
			}
			fingerprint := sha256.Sum256(data)
			contentSHA256 := fmt.Sprintf("%x", fingerprint)

			if jsWants {
				findings = append(findings, analyzeJSTaintSnapshot(ctx, path, contentSHA256, data, jsGaps)...)
			}

			if phpWants {
				findings = append(findings, analyzePHPTaintSnapshot(ctx, path, contentSHA256, data, phpGaps)...)
				phpConsumer.advance(path)
			}

			if !yaraWants {
				continue
			}
			yaraSHA256 := contentSHA256
			// Within the deep-scan size budget but possibly too large for one
			// inline IPC frame once JSON base64 expands it; the helper retries
			// by path so a payload cannot be hidden behind the inline ceiling.
			// JS analysis is unaffected: it already consumed the snapshot above.
			// #nosec G115 -- maxBytes is FullScanMaxFileBytes (int) widened to int64; the round-trip back to int is lossless.
			matches, scannedSHA, scanErr := yara.ScanContentOrPathChecked(backend, path, data, int(maxBytes))
			if scannedSHA != "" {
				yaraSHA256 = scannedSHA
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
					ContentSHA256: yaraSHA256,
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
			advanceAll(subtreePrefix(root))
		}
	}
	if ctx.Err() != nil {
		// The runner drops every finding a check returns after its budget
		// expired, so there is nothing worth reporting; leave every cursor
		// untouched and let the next run redo this window.
		return nil
	}
	resetDisabledCursors()

	now := yaraDeepNow().UTC()
	if db != nil {
		for _, c := range consumers {
			if !c.dispatch {
				continue
			}
			var next store.ScanCursorRecord
			next.Check = c.name
			if stoppedEarly {
				next.LastPath = c.lastScanned
				next.LastFullCycleTS = c.cur.LastFullCycleTS
				next.WrappedAt = c.cur.WrappedAt
				if next.WrappedAt.IsZero() {
					next.WrappedAt = now
				}
			} else {
				next.LastFullCycleTS = now
			}
			if err := db.PutScanCursor(next); err != nil {
				fmt.Fprintf(os.Stderr, "%s: cursor write: %v\n", c.name, err)
			}
		}
	}

	if yaraConsumer.dispatch {
		// A run that resumed mid-cycle or stopped at the soft deadline saw
		// only a window of the space; completing it would purge findings
		// discovered by the other windows of this cycle.
		if stoppedEarly || yaraConsumer.resume != "" {
			markCheckIncomplete(ctx, "yara_deep")
		}
		if stoppedEarly && !yaraConsumer.cur.WrappedAt.IsZero() && now.Sub(yaraConsumer.cur.WrappedAt) > yaraDeepFullCycleStale {
			findings = append(findings, alert.Finding{
				Severity: alert.Warning,
				Check:    "yara_scan_incomplete",
				Message:  fmt.Sprintf("Rolling YARA deep scan has not completed a full pass since %s", yaraConsumer.cur.WrappedAt.Format("2006-01-02")),
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
	}

	if phpConsumer.dispatch {
		phpPartial := stoppedEarly || phpConsumer.resume != "" || unknownRangeGap
		if phpPartial {
			// Only a partial or unknown-range window suppresses the normal
			// purge; a known-path gap is handled by the carry-forward below.
			markCheckIncomplete(ctx, logicalOwnerPHPTaintDeep)
		}
		if !phpGaps.empty() {
			findings = append(findings, phpGaps.finding())
		}
		if !phpPartial && st != nil {
			// Path-specific carry-forward: this run is eligible to replace the
			// PHP finding set, so a known-path coverage gap must re-emit that
			// path's prior finding or the purge would clear it. A completed
			// negative or missing path stays cleared.
			findings = append(findings, carryForwardPHPTaintFindings(st.LatestFindings(), phpGaps)...)
		}
	}

	if jsConsumer.dispatch {
		jsPartial := stoppedEarly || jsConsumer.resume != "" || unknownRangeGap
		if jsPartial {
			// Only a partial or unknown-range window suppresses the normal JS
			// purge; a known-path gap is handled by the carry-forward below.
			markCheckIncomplete(ctx, logicalOwnerJSTaintDeep)
		}
		if !jsGaps.empty() {
			findings = append(findings, jsGaps.finding())
		}
		if !jsPartial && st != nil {
			// Path-specific carry-forward: this run is eligible to replace
			// the JS finding set, so a known-path coverage gap must re-emit
			// that path's prior finding or the purge would clear it. A
			// completed negative or missing path stays cleared.
			findings = append(findings, carryForwardJSTaintFindings(st.LatestFindings(), jsGaps)...)
		}
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
