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
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/signatures"
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
	// staleCheck and label name this consumer in its own staleness finding.
	// Coverage degradation must be reported under the consumer that actually
	// degraded, never under a sibling's identity.
	staleCheck string
	label      string
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

// scheduledYARADetails describes one deep-scan match. A loader is only half
// a backdoor: the payload it pulls in lives elsewhere and survives a clean-up
// of the matched file alone, so any non-executable file this content includes
// is named alongside the rule.
func scheduledYARADetails(ruleName string, content []byte) string {
	return fmt.Sprintf("Scheduled deep scan matched YARA rule %s", ruleName) +
		signatures.ReferencedPayloadDetail(content)
}

// scheduledYARAFinding is the finding for one deep-scan match. contentSHA256
// names the bytes the backend actually scanned.
func scheduledYARAFinding(match yara.Match, path string, content []byte, contentSHA256 string) alert.Finding {
	return alert.Finding{
		Severity:      yaraMatchSeverity(match.Meta["severity"]),
		Check:         "yara_match_scheduled",
		Message:       fmt.Sprintf("YARA rule match [%s]: %s", match.RuleName, path),
		Details:       scheduledYARADetails(match.RuleName, content),
		FilePath:      path,
		ContentSHA256: contentSHA256,
		DetectLogic:   ContentDetectionVersion(),
		CoverageScope: deepFileCoverageScope(path),
	}
}

// deepFileCoverageScope names one file as the unit a partial deep-scan run
// retires once its window has examined that path.
func deepFileCoverageScope(path string) string {
	return "file:" + path
}

type yaraDeepScanEntry struct {
	path      string
	sortKey   string
	info      os.FileInfo
	err       error
	inspected bool
	directory bool
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
	w := &yaraDeepWalk{
		ctx:          ctx,
		yaraConsumer: &deepScanConsumer{name: yaraDeepCursorCheck, staleCheck: "yara_scan_incomplete", label: "YARA"},
		jsConsumer:   &deepScanConsumer{name: jsTaintDeepCursorCheck, staleCheck: "js_taint_scan_incomplete", label: "JS taint"},
		phpConsumer:  &deepScanConsumer{name: phpTaintDeepCursorCheck, staleCheck: "php_taint_scan_incomplete", label: "PHP taint"},
	}
	w.consumers = []*deepScanConsumer{w.yaraConsumer, w.jsConsumer, w.phpConsumer}

	yaraOff := yaraDeepConsumerDisabled(cfg)
	jsOff := jsTaintDeepConsumerDisabled(cfg)
	w.jsConsumer.dispatch = !jsOff
	phpOff := phpTaintDeepConsumerDisabled(cfg)
	phpReady := phpTaintAnalyzerReady()
	// An absent isolated analyzer is not a coverage gap: it means the feature
	// is not active on this host. Dispatching anyway would record every
	// candidate as unexamined on every scan.
	w.phpConsumer.dispatch = !phpOff && phpReady
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

	w.backend = activeYARABackend()
	yaraReady := w.backend != nil && w.backend.RuleCount() > 0
	w.yaraConsumer.dispatch = !yaraOff && yaraReady
	if !yaraOff && !yaraReady {
		// A missing backend is a YARA coverage gap, never a JS one: mark only
		// the YARA owner incomplete and leave its cursor unchanged so it can
		// neither purge nor skip its own unscanned range, while the JS pass
		// below still covers its cycle.
		markCheckIncomplete(ctx, "yara_deep")
		if yaraAvailable() {
			w.findings = append(w.findings, alert.Finding{
				Severity: alert.High,
				Check:    "yara_scan_incomplete",
				Message:  "YARA deep scan could not start because no compiled rules are available",
			})
		}
	}
	if !w.yaraConsumer.dispatch && !w.jsConsumer.dispatch && !w.phpConsumer.dispatch {
		if ctx.Err() != nil {
			return nil
		}
		resetDisabledCursors()
		return w.findings
	}
	w.maxBytes = int64(FullScanMaxFileBytes(cfg))
	w.jsMaxBytes = int64(jstaint.MaxSourceBytes)
	w.phpMaxBytes = int64(phptaint.MaxSourceBytes)

	for _, c := range w.consumers {
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

	rescanGen := pendingSignatureRescan(cfg, db, w.yaraConsumer.dispatch)

	// The shared walk starts at the earliest dispatchable resume point; a
	// consumer whose cursor is ahead skips already-covered paths via wants()
	// while the lagging consumer catches up on the same snapshot reads.
	firstResume := true
	for _, c := range w.consumers {
		if !c.dispatch {
			continue
		}
		if firstResume || c.resume < w.walkResume {
			w.walkResume = c.resume
			firstResume = false
		}
	}

	if deadline, ok := ctx.Deadline(); ok {
		w.softDeadline = deadline.Add(-yaraDeepDeadlineMargin)
	}

	// The collector owns both the count and the per-status breakdown, so the
	// finding can say what the gaps were instead of only how many.
	w.yaraGaps = newYARAGapCollector()
	w.yaraGaps.resolveAliases = w.resolveObservedAliases
	w.jsGaps = newJSTaintGapCollector()
	w.phpGaps = newPHPTaintGapCollector()
	w.jsGaps.resolveAliases = w.resolveObservedAliases
	w.phpGaps.resolveAliases = w.resolveObservedAliases
	w.jsGaps.recordCoverage = func(paths []string) {
		recordCoverageGapPaths(ctx, logicalOwnerJSTaintDeep, paths)
	}
	w.phpGaps.recordCoverage = func(paths []string) {
		recordCoverageGapPaths(ctx, logicalOwnerPHPTaintDeep, paths)
	}
	roots, rootsComplete := deepScanRoots(cfg)

	// Restarting the walk on updates would starve paths that sort last.
	// Track a lap from the current position instead. Changed or unresolved
	// roots invalidate that proof: a new root behind the cursor may not have
	// been visited on the return lap. The walk itself keeps its position.
	rootsHash := ""
	if rootsComplete {
		rootsHash = fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(roots, "\x00"))))
	}
	if (rescanGen != 0 && w.yaraConsumer.cur.RulesGeneration != rescanGen) ||
		(w.yaraConsumer.cur.RulesGeneration != 0 && (w.yaraConsumer.cur.RulesRootsHash != rootsHash || !rootsComplete)) {
		if rescanGen != 0 {
			w.yaraConsumer.cur.RulesGeneration = rescanGen
		}
		w.yaraConsumer.cur.RulesFrom = w.yaraConsumer.resume
		w.yaraConsumer.cur.RulesWrapped = false
		w.yaraConsumer.cur.RulesRootsHash = rootsHash
	}

	w.roots = roots
	w.walk(roots)
	if ctx.Err() != nil {
		// The runner drops every finding a check returns after its budget
		// expired, so there is nothing worth reporting; leave every cursor
		// untouched and let the next run redo this window.
		return nil
	}
	resetDisabledCursors()

	now := yaraDeepNow().UTC()
	w.saveCursors(db, now, rootsComplete)
	if rescanGen != 0 && rootsComplete {
		w.clearSignatureRescan(db, rescanGen)
	}
	w.reportStaleCycles(now)
	w.reportCoverage(st)
	return w.findings
}

// yaraDeepWalk is one run of the shared deep-content walk: the three
// consumers, their gap collectors, and the single ordered traversal they
// share. The fields below "shared walk state" describe that one traversal.
type yaraDeepWalk struct {
	ctx                                   context.Context
	backend                               yara.Backend
	yaraConsumer, jsConsumer, phpConsumer *deepScanConsumer
	consumers                             []*deepScanConsumer
	maxBytes, jsMaxBytes, phpMaxBytes     int64
	yaraGaps                              *yaraGapCollector
	jsGaps                                *jsTaintGapCollector
	phpGaps                               *phpTaintGapCollector
	findings                              []alert.Finding

	// Shared walk state. walkResume is the earliest dispatching resume point.
	roots        []string
	walkResume   string
	softDeadline time.Time
	stoppedEarly bool
	// observedPath and observedInfo are the identity last observed for a
	// path, so a later failure on it can be pinned to that exact file.
	observedPath string
	observedInfo os.FileInfo
}

// deepFileWants records which consumers still need the file being read.
type deepFileWants struct{ yara, js, php bool }

func (fw deepFileWants) any() bool { return fw.yara || fw.js || fw.php }

func (w *yaraDeepWalk) outOfTime() bool {
	return !w.softDeadline.IsZero() && !yaraDeepNow().Before(w.softDeadline)
}

func (w *yaraDeepWalk) observePathIdentity(path string, info os.FileInfo) {
	w.observedPath = path
	w.observedInfo = info
}

func (w *yaraDeepWalk) resolveObservedAliases(path string) ([]string, bool) {
	if path != w.observedPath || w.observedInfo == nil {
		return coveragePathAliases(path), false
	}
	return stableCoveragePathAliases(path, w.observedInfo)
}

func (w *yaraDeepWalk) pathFailureStillAttributable(path string) (os.FileInfo, bool) {
	info, err := osFS.Lstat(path)
	// Every metadata error is ambiguous, including ENOENT: a delete can race
	// this observation and replace the path with a directory immediately after
	// it. Only an observed non-directory, non-symlink entry is narrow enough to
	// preserve by exact path.
	return info, err == nil && !info.IsDir() && info.Mode()&os.ModeSymlink == 0 &&
		w.observedPath == path && w.observedInfo != nil && os.SameFile(w.observedInfo, info)
}

func (w *yaraDeepWalk) recordYARAPathGap(path, status string) {
	recordCoverageGapPaths(w.ctx, "yara_deep", w.yaraGaps.record(path, status))
}

func (w *yaraDeepWalk) recordYARAScanGap(path string, scanErr error) {
	// Inline IPC overflow retries by path. If that path changed into a
	// directory or symlink before the retry failed, the unscanned range is no
	// longer just the original file: children or a target subtree may now be
	// hidden. The post-failure Lstat is inherently racy, so every metadata
	// error takes the conservative unknown-range path.
	info, attributable := w.pathFailureStillAttributable(path)
	if !attributable {
		w.yaraGaps.recordUnknownRange(fmt.Sprintf("scanning %s failed after the path changed: %v", path, scanErr))
		return
	}
	w.observePathIdentity(path, info)
	w.recordYARAPathGap(path, "scan_error")
}

// recordUnknownRange records a loss whose affected paths are unknowable for
// every consumer in fw.
func (w *yaraDeepWalk) recordUnknownRange(fw deepFileWants, detail string) {
	if fw.yara {
		w.yaraGaps.recordUnknownRange(detail)
	}
	if fw.js {
		w.jsGaps.recordUnknownRange(detail)
	}
	if fw.php {
		w.phpGaps.recordUnknownRange(detail)
	}
}

// recordPathGap records an exact-path gap for every consumer in fw. YARA
// keeps its own status where its report names the failure differently.
func (w *yaraDeepWalk) recordPathGap(fw deepFileWants, path, yaraStatus, status string) {
	if fw.yara {
		w.recordYARAPathGap(path, yaraStatus)
	}
	if fw.js {
		w.jsGaps.record(path, status)
	}
	if fw.php {
		w.phpGaps.record(path, status)
	}
}

func (w *yaraDeepWalk) advanceAll(path string) {
	for _, c := range w.consumers {
		c.advance(path)
	}
}

// deepSubtreePrefix is the sort key every path under dir starts with.
func deepSubtreePrefix(path string) string {
	sep := string(filepath.Separator)
	path = filepath.Clean(path)
	if strings.HasSuffix(path, sep) {
		return path
	}
	return path + sep
}

// deepSubtreeCoveredAfter reports whether every path under dir sorts before
// resume. Children all share the dir+sep prefix, so when resume does not
// itself start with that prefix, any child compares to resume exactly as the
// prefix does. Comparing the bare dir path instead would wrongly skip
// siblings like "ab/" when the cursor sits at "ab.zz" ('/' sorts after '.').
// An exact prefix cursor records a subtree already accounted for this cycle,
// including an empty or unreadable directory.
func deepSubtreeCoveredAfter(resume, dir string) bool {
	prefix := deepSubtreePrefix(dir)
	return resume != "" && (resume == prefix || (!strings.HasPrefix(resume, prefix) && prefix < resume))
}

// deepScanRoots returns the web roots deduplicated and in walk order, and
// whether every root resolved.
func deepScanRoots(cfg *config.Config) ([]string, bool) {
	roots, rootsComplete := resolveWebRootsChecked(cfg)
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
	sort.Slice(roots, func(i, j int) bool { return deepSubtreePrefix(roots[i]) < deepSubtreePrefix(roots[j]) })
	return roots, rootsComplete
}

func (w *yaraDeepWalk) walk(roots []string) {
	// All roots share one frontier. Walking an outer root to completion
	// first can pass a nested symlink root that only an explicit root visit
	// follows, falsely placing its unread files inside the retirement window.
	ordered := make(yaraDeepScanHeap, len(roots))
	rootSet := make(map[string]bool, len(roots))
	for i, root := range roots {
		rootSet[root] = true
		ordered[i] = yaraDeepScanEntry{path: root, sortKey: deepSubtreePrefix(root), inspected: true, directory: true}
	}
	heap.Init(&ordered)

	for ordered.Len() > 0 {
		if w.ctx.Err() != nil || w.stoppedEarly {
			return
		}
		if w.outOfTime() {
			w.stoppedEarly = true
			return
		}
		item := heap.Pop(&ordered).(yaraDeepScanEntry)
		if !item.inspected {
			item.info, item.err = osFS.Lstat(item.path)
			item.inspected = true
			if item.err == nil && item.info.Mode()&os.ModeSymlink == 0 && item.info.IsDir() {
				// Bare names are lower bounds. Children of ab/ sort after
				// ab.zz, so a discovered directory must be requeued.
				item.directory = true
				item.sortKey = deepSubtreePrefix(item.path)
				heap.Push(&ordered, item)
				continue
			}
		}
		if item.directory {
			if !deepSubtreeCoveredAfter(w.walkResume, item.path) {
				w.enqueueDir(item.path, &ordered, rootSet)
			}
			continue
		}
		w.scanFile(item.path, item.info, item.err)
	}
}

func (w *yaraDeepWalk) enqueueDir(dir string, ordered *yaraDeepScanHeap, roots map[string]bool) {
	entries, err := osFS.ReadDir(dir)
	if err != nil {
		// The affected paths are unknowable, but a consumer that already
		// covered this subtree must not inherit another consumer's gap.
		w.recordUnknownRange(deepFileWants{
			yara: w.yaraConsumer.dispatch && !deepSubtreeCoveredAfter(w.yaraConsumer.resume, dir),
			js:   w.jsConsumer.dispatch && !deepSubtreeCoveredAfter(w.jsConsumer.resume, dir),
			php:  w.phpConsumer.dispatch && !deepSubtreeCoveredAfter(w.phpConsumer.resume, dir),
		}, fmt.Sprintf("reading %s: %v", dir, err))
		w.advanceAll(deepSubtreePrefix(dir))
		return
	}
	if len(entries) == 0 {
		// A prefix cursor covers the entire subtree, so it is safe before
		// visiting children only when there are none. Nonempty directories
		// advance through their children, whose paths exceed this prefix.
		w.advanceAll(deepSubtreePrefix(dir))
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if !roots[path] {
			heap.Push(ordered, yaraDeepScanEntry{path: path, sortKey: path})
		}
	}
}

// scanFile hands one walked non-directory entry to every consumer that
// still needs it. It sets stoppedEarly when the soft deadline passes before
// the read.
func (w *yaraDeepWalk) scanFile(path string, info os.FileInfo, lstatErr error) {
	fw := deepFileWants{
		yara: w.yaraConsumer.wants(path),
		js:   w.jsConsumer.wants(path),
		php:  w.phpConsumer.wants(path),
	}
	if !fw.any() {
		return
	}
	if lstatErr != nil {
		// A failed Lstat may hide a directory, so the gap range is
		// unknowable for either path-based carry-forward.
		w.recordUnknownRange(fw, fmt.Sprintf("inspecting %s: %v", path, lstatErr))
		w.advanceAll(path)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() == 0 {
		w.advanceAll(path)
		return
	}
	w.observePathIdentity(path, info)
	if fw.yara && info.Size() > w.maxBytes {
		// Oversize files are intentionally not opened, but they still
		// count as covered progress for this rolling cycle. The gap
		// advances only its own consumer: a soft-deadline stop right
		// after this gate must not move the other consumer past a
		// file it never received.
		w.recordYARAPathGap(path, "oversize")
		w.yaraConsumer.advance(path)
		fw.yara = false
	}
	if fw.php && info.Size() > w.phpMaxBytes {
		// An oversize file is only a PHP coverage gap if it could have
		// been PHP. The deep walk hands every readable file to this
		// consumer and the analyzer's own pre-filter normally rejects
		// the rest instantly -- but that pre-filter never runs on a
		// file too large to send, so without this check every large
		// error_log, JSON blob and media file on the host is reported
		// as PHP content we failed to examine. Measured on a live
		// host: 617 of 660 recorded gaps in one scan, which buries the
		// handful that are real.
		// Past the soft deadline the walk is stopping and must do
		// no further I/O, so the peek is skipped and the gap is
		// recorded unexamined -- the same answer an unreadable
		// file gets.
		if w.outOfTime() || phpFileMayBePHP(path, info) {
			w.phpGaps.record(path, phptaint.StatusOversize.String())
		}
		w.phpConsumer.advance(path)
		fw.php = false
	}
	if fw.js && info.Size() > w.jsMaxBytes {
		// An oversize file is only a JS coverage gap if it could
		// have been JavaScript. The deep walk hands every readable
		// file to this consumer and the analyzer's own pre-filter
		// normally rejects the rest instantly -- but that pre-filter
		// never runs on a file too large to send, so without this
		// check every large image, archive and database on the host
		// is reported as JavaScript we failed to examine. This gate
		// was missing while the PHP one beside it existed.
		//
		// This branch used to decide on metadata alone. Peeking
		// costs an open, so as with PHP above it is skipped once the
		// soft deadline has passed and the gap is recorded
		// unexamined.
		if w.outOfTime() || jsFileMayBeJS(path, info) {
			w.jsGaps.record(path, jstaint.StatusOversize.String())
		}
		w.jsConsumer.advance(path)
		fw.js = false
	}
	if !fw.any() {
		return
	}
	if w.outOfTime() {
		w.stoppedEarly = true
		return
	}
	// Advance before opening so permanently unreadable or unscannable
	// files cannot wedge the cursor in place.
	w.advanceAll(path)

	data, ok := w.readSnapshot(path, &fw)
	if !ok {
		return
	}
	fingerprint := sha256.Sum256(data)
	contentSHA256 := fmt.Sprintf("%x", fingerprint)

	if fw.js {
		w.findings = append(w.findings, analyzeJSTaintSnapshot(w.ctx, path, contentSHA256, data, w.jsGaps)...)
	}
	if fw.php {
		w.findings = append(w.findings, analyzePHPTaintSnapshot(w.ctx, path, contentSHA256, data, w.phpGaps)...)
		w.phpConsumer.advance(path)
	}
	if !fw.yara {
		return
	}
	matches, scanErr := yara.ScanBytesChecked(w.backend, path, data)
	if scanErr != nil {
		w.recordYARAScanGap(path, scanErr)
		return
	}
	for _, match := range matches {
		w.findings = append(w.findings, scheduledYARAFinding(match, path, data, contentSHA256))
	}
}

// readSnapshot reads path once, capped at the largest limit among the
// consumers in fw. A consumer the file no longer fits, or that cannot get a
// stable snapshot, records its gap and leaves fw. ok is false when no
// consumer is left to receive the content.
func (w *yaraDeepWalk) readSnapshot(path string, fw *deepFileWants) ([]byte, bool) {
	file, err := osFS.Open(path)
	if err != nil {
		if info, attributable := w.pathFailureStillAttributable(path); attributable {
			w.observePathIdentity(path, info)
			w.recordPathGap(*fw, path, "open_error", "read_error")
		} else {
			w.recordUnknownRange(*fw, fmt.Sprintf("opening %s: %v", path, err))
		}
		return nil, false
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		w.recordUnknownRange(*fw, fmt.Sprintf("inspecting opened path %s: %v", path, statErr))
		return nil, false
	}
	if !openedInfo.Mode().IsRegular() {
		_ = file.Close()
		if openedInfo.IsDir() {
			// Lstat admitted a regular file, but Open bound a directory.
			// Its children were never enumerated, so retaining only the
			// exact path would purge findings from an unknown subtree.
			w.recordUnknownRange(*fw, fmt.Sprintf("%s changed into a directory while it was being opened", path))
		} else {
			w.recordPathGap(*fw, path, "changed_during_read", "changed_during_read")
		}
		return nil, false
	}
	w.observePathIdentity(path, openedInfo)
	if fw.yara && openedInfo.Size() > w.maxBytes {
		w.recordYARAPathGap(path, "changed_during_read")
		fw.yara = false
	}
	if fw.php && openedInfo.Size() > w.phpMaxBytes {
		w.phpGaps.record(path, "changed_during_read")
		fw.php = false
	}
	if fw.js && openedInfo.Size() > w.jsMaxBytes {
		w.jsGaps.record(path, "changed_during_read")
		fw.js = false
	}
	if !fw.any() {
		_ = file.Close()
		return nil, false
	}
	readCap := int64(0)
	if fw.yara {
		readCap = w.maxBytes
	}
	if fw.js && w.jsMaxBytes > readCap {
		readCap = w.jsMaxBytes
	}
	if fw.php && w.phpMaxBytes > readCap {
		readCap = w.phpMaxBytes
	}
	data, readErr := io.ReadAll(io.LimitReader(file, readCap+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > readCap {
		w.recordPathGap(*fw, path, "read_error", "read_error")
		return nil, false
	}
	if fw.yara && int64(len(data)) > w.maxBytes {
		w.recordYARAPathGap(path, "read_error")
		fw.yara = false
	}
	if fw.php && int64(len(data)) > w.phpMaxBytes {
		w.phpGaps.record(path, "changed_during_read")
		fw.php = false
	}
	if fw.js && int64(len(data)) > w.jsMaxBytes {
		w.jsGaps.record(path, "changed_during_read")
		fw.js = false
	}
	return data, true
}

// saveCursors persists each dispatching consumer's progress. A completed
// walk stamps a full cycle; a stopped one keeps its resume point and the
// start of its partial cycle.
func (w *yaraDeepWalk) saveCursors(db *store.DB, now time.Time, rootsComplete bool) {
	if db == nil {
		return
	}
	for _, c := range w.consumers {
		if !c.dispatch {
			continue
		}
		var next store.ScanCursorRecord
		next.Check = c.name
		next.RulesGeneration = c.cur.RulesGeneration
		next.RulesFrom = c.cur.RulesFrom
		next.RulesWrapped = c.cur.RulesWrapped || (!w.stoppedEarly && rootsComplete && c.cur.RulesGeneration != 0)
		next.RulesRootsHash = c.cur.RulesRootsHash
		if w.stoppedEarly {
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

// clearSignatureRescan retires the queued rescan once the YARA walk has
// passed every file since the rules update that queued it.
func (w *yaraDeepWalk) clearSignatureRescan(db *store.DB, rescanGen uint64) {
	// A walk that started from where the update found it has passed every
	// file once it completes. Otherwise it must have wrapped and come back
	// to that point. A stopped walk cannot have wrapped during this run.
	cur := w.yaraConsumer.cur
	reachedFrom := w.yaraConsumer.lastScanned >= cur.RulesFrom
	if strings.HasSuffix(cur.RulesFrom, string(filepath.Separator)) {
		// A prefix cursor covers every child, not just the first path
		// that sorts after the prefix. Use the walk's subtree ordering.
		reachedFrom = deepSubtreeCoveredAfter(w.yaraConsumer.lastScanned, cur.RulesFrom)
	}
	if (!w.stoppedEarly && (cur.RulesFrom == "" || cur.RulesWrapped)) ||
		(cur.RulesWrapped && reachedFrom) {
		cleared, err := db.ClearSignatureRescan(rescanGen)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: clearing signature rescan: %v\n", w.yaraConsumer.name, err)
		} else if cleared {
			observeSignatureRescan()
		}
	}
}

// reportStaleCycles warns for each consumer whose rolling cycle has gone too
// long without a full pass.
//
// Rolling-cycle staleness is per consumer. All three keep their own cursor
// and their own WrappedAt, so the warning belongs to whichever cycle
// actually stalled. This was read from the YARA cursor alone, which left a
// stalled PHP or JS cycle silent, and silenced the warning entirely when
// yara_deep was disabled -- a supported configuration.
//
// Enumerated once so the shape is not rediscovered one field at a time.
// Persisted per-consumer state:
//
//	cur.LastPath becomes resume and lastScanned. walkResume is the minimum
//	active resume; wants and the per-consumer subtree check still gate each
//	consumer, and advance plus the cursor write update only that consumer's
//	progress.
//	cur.WrappedAt starts that consumer's partial cycle and drives only its
//	staleCheck/label warning here.
//	cur.LastFullCycleTS is preserved or stamped in that consumer's record.
//
// Runtime per-consumer state:
//
//	dispatch comes from that consumer's disable/readiness gates and controls
//	its cursor, analysis, completion mark, status finding, and carry-forward.
//	deepFileWants and the three size limits govern only the matching
//	consumer. The shared read cap is their maximum, so no sibling can reduce
//	another's snapshot.
//	yaraGaps belongs only to YARA; jsGaps only to JS; phpGaps only to PHP.
//	Each is reported and used for completion/carry-forward only in its owner
//	block of reportCoverage.
//
// Genuinely shared state:
//
//	roots, path order, the context/soft deadline, opened snapshots, and
//	stoppedEarly describe the one walk. After a consumer's resume point all
//	active consumers have the same remaining ordered path space, so a walk
//	that stops early cannot have completed one active consumer's cycle while
//	leaving another active consumer's cycle unfinished.
//
// Known and deliberately out of scope: php_content_rolling.go writes
// WrappedAt for its per-account cursor and nothing reads it, so that scan
// has no staleness warning of its own.
func (w *yaraDeepWalk) reportStaleCycles(now time.Time) {
	if !w.stoppedEarly {
		return
	}
	for _, c := range w.consumers {
		if !c.dispatch || c.cur.WrappedAt.IsZero() || now.Sub(c.cur.WrappedAt) <= yaraDeepFullCycleStale {
			continue
		}
		w.findings = append(w.findings, alert.Finding{
			Severity: alert.Warning,
			Check:    c.staleCheck,
			Message:  fmt.Sprintf("Rolling %s deep scan has not completed a full pass since %s", c.label, c.cur.WrappedAt.Format("2006-01-02")),
			Details:  "Each run advances the cursor inside its time budget; a pass this stale means the budget is too small for the content volume.",
		})
	}
}

// reportCoverage closes each dispatching consumer's window: it marks a
// partial window incomplete, reports gaps, and carries forward prior
// findings for known-path gaps when the window may replace the finding set.
func (w *yaraDeepWalk) reportCoverage(st *state.Store) {
	if w.yaraConsumer.dispatch {
		// Same contract the PHP and JS consumers use. Only a partial window or
		// an unknown-range loss suppresses the purge; a gap that names a file
		// is handled by carrying that file's prior finding forward, so the
		// scan can still retire everything it did examine. Reporting a bare
		// count here is what made one permanently unreadable file look
		// identical to a lost subtree, and froze every YARA finding on a host.
		yaraPartial := w.stoppedEarly || w.yaraConsumer.resume != "" || w.yaraGaps.pathsIncomplete()
		if yaraPartial {
			markCheckIncomplete(w.ctx, "yara_deep")
		}
		if !w.yaraGaps.empty() {
			w.findings = append(w.findings, w.yaraGaps.finding())
		}
		if yaraPartial && !w.yaraGaps.pathsIncomplete() && st != nil {
			recordCompletedCoverageScopes(w.ctx, "yara_deep",
				w.examinedScopes(w.yaraConsumer, st.LatestFindings(), "yara_match_scheduled", w.yaraGaps.hasPath))
		}
		if !yaraPartial && st != nil {
			// Keep the stable carried snapshots in-band so alert deduplication can
			// retain its normal ongoing-finding re-alert cadence. Daemon callers
			// also publish the path set for race-safe latest-state persistence.
			w.findings = append(w.findings, carryForwardYARAFindings(st.LatestFindings(), w.yaraGaps)...)
		}
	}

	if w.phpConsumer.dispatch {
		phpPartial := w.stoppedEarly || w.phpConsumer.resume != "" || w.phpGaps.pathsIncomplete()
		if phpPartial {
			// Only a partial or unknown-range window suppresses the normal
			// purge; a known-path gap is handled by the carry-forward below.
			markCheckIncomplete(w.ctx, logicalOwnerPHPTaintDeep)
		}
		if !w.phpGaps.empty() {
			w.findings = append(w.findings, w.phpGaps.findings()...)
		}
		if phpPartial && !w.phpGaps.pathsIncomplete() && st != nil {
			recordCompletedCoverageScopes(w.ctx, logicalOwnerPHPTaintDeep,
				w.examinedScopes(w.phpConsumer, st.LatestFindings(), "php_remote_taint", w.phpGaps.hasPath))
		}
		if !phpPartial && st != nil {
			// Path-specific carry-forward: this run is eligible to replace the
			// PHP finding set, so a known-path coverage gap must re-emit that
			// path's prior finding or the purge would clear it. A completed
			// negative or missing path stays cleared.
			w.findings = append(w.findings, carryForwardPHPTaintFindings(st.LatestFindings(), w.phpGaps)...)
		}
	}

	if w.jsConsumer.dispatch {
		jsPartial := w.stoppedEarly || w.jsConsumer.resume != "" || w.jsGaps.pathsIncomplete()
		if jsPartial {
			// Only a partial or unknown-range window suppresses the normal JS
			// purge; a known-path gap is handled by the carry-forward below.
			markCheckIncomplete(w.ctx, logicalOwnerJSTaintDeep)
		}
		if !w.jsGaps.empty() {
			w.findings = append(w.findings, w.jsGaps.finding())
		}
		if jsPartial && !w.jsGaps.pathsIncomplete() && st != nil {
			recordCompletedCoverageScopes(w.ctx, logicalOwnerJSTaintDeep,
				w.examinedScopes(w.jsConsumer, st.LatestFindings(), "js_keylogger_dataflow", w.jsGaps.hasPath))
		}
		if !jsPartial && st != nil {
			// Path-specific carry-forward: this run is eligible to replace
			// the JS finding set, so a known-path coverage gap must re-emit
			// that path's prior finding or the purge would clear it. A
			// completed negative or missing path stays cleared.
			w.findings = append(w.findings, carryForwardJSTaintFindings(st.LatestFindings(), w.jsGaps)...)
		}
	}
}

// examinedScopes returns the coverage scopes of prior check findings whose
// file this run's window for c examined: under a walked root, past the
// consumer's resume point, and no further than where it stopped. A partial
// run then retires exactly what a complete run would within that window. A
// gap path was not examined, so it keeps its finding.
func (w *yaraDeepWalk) examinedScopes(c *deepScanConsumer, prior []alert.Finding, check string, gap func(string) bool) map[string]bool {
	scopes := make(map[string]bool)
	for _, f := range prior {
		if f.Check != check || f.FilePath == "" || f.CoverageScope != deepFileCoverageScope(f.FilePath) {
			continue
		}
		if !w.underRoot(f.FilePath) || deepPathCoveredBy(c.resume, f.FilePath) ||
			(w.stoppedEarly && !deepPathCoveredBy(c.lastScanned, f.FilePath)) || gap(f.FilePath) {
			continue
		}
		scopes[f.CoverageScope] = true
	}
	return scopes
}

func (w *yaraDeepWalk) underRoot(path string) bool {
	for _, root := range w.roots {
		if strings.HasPrefix(path, deepSubtreePrefix(root)) {
			return true
		}
	}
	return false
}

// deepPathCoveredBy reports whether a cursor has already passed path in walk
// order: a cursor ending in a separator covers that whole subtree, and any
// other cursor covers every path up to and including itself.
func deepPathCoveredBy(cursor, path string) bool {
	if cursor == "" {
		return false
	}
	if strings.HasSuffix(cursor, string(filepath.Separator)) && strings.HasPrefix(path, cursor) {
		return true
	}
	return path <= cursor
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

var (
	sigRescansTotalOnce sync.Once
	sigRescansTotal     *metrics.Counter
)

// observeSignatureRescan counts a queued rescan cleared because the walk
// has scanned every file since the rules update that queued it.
func observeSignatureRescan() {
	sigRescansTotalOnce.Do(func() {
		sigRescansTotal = metrics.NewCounter(
			"csm_signature_rescans_total",
			"Rescans queued by a signature update that completed. Incremented when the rolling deep YARA walk has scanned every file since the update.",
		)
		metrics.MustRegister("csm_signature_rescans_total", sigRescansTotal)
	})
	sigRescansTotal.Inc()
}

// pendingSignatureRescan returns the queued rescan generation the YARA walk
// should cover, or 0 when there is none to track. Disabled rescans pause the
// queue, and an unreadable queue is left for the watcher to repair.
func pendingSignatureRescan(cfg *config.Config, db *store.DB, dispatch bool) uint64 {
	if !dispatch || db == nil || !cfg.SignatureRescanEnabled() {
		return 0
	}
	gen, err := db.SignatureRescanPending()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: reading signature rescan: %v\n", yaraDeepCursorCheck, err)
		return 0
	}
	return gen
}
