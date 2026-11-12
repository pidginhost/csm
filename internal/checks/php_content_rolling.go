package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/contenttype"
	"github.com/pidginhost/csm/internal/store"
)

// rollingScanCheck is the cursor key under which rolling content coverage
// records its per-account progress. It reuses the existing content findings, so
// no new check name is registered.
const rollingScanCheck = "php_content"

// rollingWalkMaxDepth bounds how deep enumeratePHPFiles descends under each
// docroot, so a deeply nested or symlink-looped tree cannot make enumeration
// unbounded. The fixed suspicious-dir scan uses a shallow depth; rolling needs
// to reach app code nested a few levels down (e.g. wp-content/plugins/x/inc/y)
// but does not need to chase arbitrarily deep trees.
const rollingWalkMaxDepth = 12

// rollingContentEnabled gates rolling coverage to normal periodic host-wide
// runs: the knob is on, this is not an account-scoped run, and it is not a
// forced/audit full content scan (those already read every file). forcedFull is
// the per-cycle decision already computed by CheckPHPContent
// (phpContentForceFull || scanForceContent); it is threaded in rather than
// recomputed because phpContentForceFull advances a cadence counter on each
// call, so calling it twice per cycle would skew the forced-rescan cadence.
func rollingContentEnabled(ctx context.Context, cfg *config.Config, forcedFull bool) bool {
	return cfg.Thresholds.RollingCoverage &&
		AccountFromContext(ctx) == "" &&
		!forcedFull
}

// rollingContentPass spends one cycle's file budget on rolling coverage across
// the host. The budget is the operator's per-scan file cap: sizing a window
// that large for every account asked for hundreds of windows inside one check
// budget, so the check never finished and its findings were never reported.
// Accounts are taken least-recently-covered first, so a host too large for one
// cycle keeps moving instead of resweeping the same alphabetical prefix.
func rollingContentPass(ctx context.Context, cfg *config.Config, scan *phpContentScan, homeDirs []os.DirEntry, findings *[]alert.Finding) {
	db := store.Global()
	if db == nil {
		// Cannot persist a cursor, so rolling would scan from the start every
		// cycle without making progress. Skip rather than spin in place.
		return
	}
	rollingContentCursors.retain(db, homeDirs)
	accounts := rollingAccountOrder(db, homeDirs)
	budget := accountScanMaxFiles(ctx, cfg)
	budget -= rollingChangedPass(ctx, cfg, scan, db, accounts, budget, findings)
	wrapped := 0
	for _, account := range accounts {
		if ctx.Err() != nil || budget <= 0 {
			break
		}
		whole, used := rollingContentCoverage(ctx, cfg, scan, account.name, accountDocRoots(account.home), budget, findings)
		budget -= used
		if whole {
			wrapped++
		}
	}
	if wrapped != len(accounts) {
		// The accounts this cycle did not finish are not re-emitting their
		// earlier findings, and completing the check would purge them
		// (mirrors yara_deep).
		markCheckIncomplete(ctx, "php_content")
	}
}

// rollingAccount pairs an account name with its home directory.
type rollingAccount struct {
	name string
	home string
}

// rollingAccountOrder sorts accounts by the time each last completed a full
// traversal, oldest first, so an account that has never been covered goes
// first and no account can be starved by the ones before it in the alphabet.
func rollingAccountOrder(db *store.DB, homeDirs []os.DirEntry) []rollingAccount {
	type ordered struct {
		rollingAccount
		last time.Time
	}
	all := make([]ordered, 0, len(homeDirs))
	for _, entry := range homeDirs {
		if !entry.IsDir() {
			continue
		}
		cur, _ := rollingContentCursors.load(db, entry.Name())
		all = append(all, ordered{
			rollingAccount: rollingAccount{name: entry.Name(), home: scanHomeDirPath(entry)},
			last:           cur.LastFullCycleTS,
		})
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].last.Equal(all[j].last) {
			return all[i].last.Before(all[j].last)
		}
		return all[i].name < all[j].name
	})
	out := make([]rollingAccount, 0, len(all))
	for _, a := range all {
		out = append(out, a.rollingAccount)
	}
	return out
}

// rollingContentCoverage sweeps a bounded path-sorted slice of the account's
// full docroot PHP-source set, advancing the per-account cursor so every stock
// PHP source or source-view file is eventually content-scanned over cycles.
// The caller guarantees the gate (rolling on, host-scope periodic, not a
// forced/audit run) and hands it what is left of the cycle's file budget.
// Findings append to the live findings slice (rolling is part of the periodic
// scan, not a report-only full-scan job). A canceled run leaves the prior
// cursor untouched. It returns how many files it read so the caller can charge
// them against the budget.
//
// Limitation: rolling enumerates only stock-PHP-executable filenames across the
// whole docroot. A file whose non-stock extension is remapped to PHP by an
// .htaccess handler (the LEVIATHAN trick) is NOT enumerated here; the fixed
// suspicious-dir scan (which layers per-directory overlays as it descends) and
// realtime fanotify still cover those.
// It reports whether this cycle covered the account's whole file list. A
// window that did not wrap leaves files from earlier windows unvisited, and
// their findings are not re-emitted this cycle, so the caller must mark the
// check incomplete or the runner purges them from the latest set.
func rollingContentCoverage(ctx context.Context, cfg *config.Config, scan *phpContentScan, account string, docRoots []string, limit int, findings *[]alert.Finding) (bool, int) {
	db := store.Global()

	files := enumeratePHPFiles(ctx, cfg, docRoots)
	if ctx.Err() != nil {
		return false, 0
	}
	// Enumeration already covers all roots independently of the content
	// window. Prune even on partial or empty windows, including lists that
	// keep growing before the cursor can ever wrap.
	scan.pruneMissing(docRoots, files)
	if len(files) == 0 {
		return true, 0
	}

	cur, curErr := rollingContentCursors.load(db, account)
	if curErr != nil {
		// Keep storage failures visible even when in-memory progress lets
		// this daemon continue covering the account.
		fmt.Fprintf(os.Stderr, "php_content rolling: cursor read for %s: %v\n", account, curErr)
	}
	selected, newLast, wrapped := rollingCandidatesAfter(files, cur.LastPath, limit)
	if len(selected) == 0 {
		return true, 0
	}
	// Crossing the end of the list completes a traversal across several
	// windows, but this run still did not re-emit findings from the earlier
	// windows. Only a window containing the whole list is safe to report as a
	// completed check to the runner.
	windowComplete := len(selected) == len(files)
	fullTraversal := wrapped || windowComplete

	// Reconstruct the .htaccess handler overlay once per directory: every file
	// in the slice that shares a directory shares the same overlay, and reading
	// the ancestor .htaccess chain per file would multiply the read cost.
	overlayCache := make(map[string]phpHandlerOverlay)
	read := 0
	for _, file := range selected {
		if ctx.Err() != nil {
			break
		}
		// The fixed walk or the changed pass already read it this cycle.
		if _, done := scan.attempted[file]; done {
			continue
		}
		// Opening FIFOs or device nodes can block the scan; rolling only needs
		// regular PHP files (including symlinks that resolve to regular files).
		if !rollingRegularCandidate(file) {
			// A failed stat or changed file type invalidates any earlier
			// clean result just like an unsuccessful content read.
			delete(scan.prev, file)
			delete(scan.next, file)
			continue
		}
		read++
		dir := filepath.Dir(file)
		overlay, ok := overlayCache[dir]
		if !ok {
			overlay = reconstructOverlay(rollingDocRootFor(file, docRoots), dir)
			overlayCache[dir] = overlay
		}
		scan.scanFile(ctx, file, overlay, findings)
	}

	// Advance the cursor only on a complete, uncanceled run. A run cut short by
	// ctx cancellation leaves the prior cursor so the next cycle resumes where
	// this one stopped instead of skipping the unscanned tail.
	if ctx.Err() != nil {
		return false, read
	}
	cur.Account = account
	cur.Check = rollingScanCheck
	cur.LastPath = newLast
	if fullTraversal {
		now := time.Now().UTC()
		cur.LastFullCycleTS = now
		if wrapped {
			cur.WrappedAt = now
		}
	}
	if err := rollingContentCursors.save(db, cur); err != nil {
		fmt.Fprintf(os.Stderr, "php_content rolling: cursor write for %s: %v\n", account, err)
	}
	return windowComplete, read
}

// rollingChangedMargin is taken off a pass's start time before it becomes an
// account's watermark, so a clock stepped back by less than this cannot hide
// a file changed right after the pass. Var, not const, so tests can zero it.
var rollingChangedMargin = 2 * time.Minute

// rollingChangedPass reads, before any rolling window, the files changed since
// each account's watermark: written, replaced or modified after it. Accounts
// are listed each cycle until the budget runs out, so a file planted outside
// the fixed directories is read within a cycle instead of when a window
// reaches it. Accounts served longest ago go first, and an account the budget
// cuts short resumes after the last file read. It returns how many files it
// read.
func rollingChangedPass(ctx context.Context, cfg *config.Config, scan *phpContentScan, db *store.DB, accounts []rollingAccount, budget int, findings *[]alert.Finding) int {
	start := phpContentNow()
	read := 0
	for _, account := range rollingChangedOrder(db, accounts) {
		if ctx.Err() != nil || read >= budget {
			break
		}
		read += rollingChangedAccount(ctx, cfg, scan, db, account, start, budget-read, findings)
	}
	return read
}

func rollingChangedOrder(db *store.DB, accounts []rollingAccount) []rollingAccount {
	type ordered struct {
		rollingAccount
		served time.Time
	}
	all := make([]ordered, 0, len(accounts))
	for _, account := range accounts {
		cur, _ := rollingContentCursors.load(db, account.name)
		all = append(all, ordered{rollingAccount: account, served: cur.ChangedServedAt})
	}
	sort.SliceStable(all, func(i, j int) bool {
		if !all[i].served.Equal(all[j].served) {
			return all[i].served.Before(all[j].served)
		}
		return all[i].name < all[j].name
	})
	out := make([]rollingAccount, 0, len(all))
	for _, a := range all {
		out = append(out, a.rollingAccount)
	}
	return out
}

func rollingChangedAccount(ctx context.Context, cfg *config.Config, scan *phpContentScan, db *store.DB, account rollingAccount, start time.Time, limit int, findings *[]alert.Finding) int {
	cur, curErr := rollingContentCursors.load(db, account.name)
	if curErr != nil {
		fmt.Fprintf(os.Stderr, "php_content changed pass: cursor read for %s: %v\n", account.name, curErr)
	}
	cur.Account, cur.Check = account.name, rollingScanCheck
	if cur.ChangedThrough.IsZero() {
		// First sight: files already here are the rolling windows' job.
		cur.ChangedThrough = start.Add(-rollingChangedMargin)
		saveRollingCursor(db, cur)
		return 0
	}
	roots := accountDocRoots(account.home)
	files := enumeratePHPFiles(ctx, cfg, roots)
	if ctx.Err() != nil {
		return 0
	}
	changed := scan.changedSince(files, cur.ChangedThrough)
	lapStart := cur.ChangedLapStart
	if lapStart.IsZero() {
		lapStart = start
	}
	if len(changed) == 0 {
		if cur.ChangedFrom != "" {
			// What the cut-short lap had left is gone.
			cur.ChangedThrough = lapStart.Add(-rollingChangedMargin)
			cur.ChangedFrom, cur.ChangedLapStart = "", time.Time{}
			saveRollingCursor(db, cur)
		}
		return 0
	}
	ordered := rotateAfter(changed, cur.ChangedFrom)
	overlays := make(map[string]phpHandlerOverlay)
	read, next := 0, 0
	for ; next < len(ordered) && read < limit; next++ {
		if ctx.Err() != nil {
			// Leave the cursor: the next cycle reads this lap again.
			return read
		}
		file := ordered[next]
		if !rollingRegularCandidate(file) {
			delete(scan.prev, file)
			delete(scan.next, file)
			continue
		}
		read++
		dir := filepath.Dir(file)
		overlay, ok := overlays[dir]
		if !ok {
			overlay = reconstructOverlay(rollingDocRootFor(file, roots), dir)
			overlays[dir] = overlay
		}
		scan.scanFile(ctx, file, overlay, findings)
	}
	if next == len(ordered) {
		cur.ChangedThrough = lapStart.Add(-rollingChangedMargin)
		cur.ChangedFrom, cur.ChangedLapStart = "", time.Time{}
	} else {
		cur.ChangedFrom, cur.ChangedLapStart = ordered[next-1], lapStart
	}
	cur.ChangedServedAt = start
	saveRollingCursor(db, cur)
	return read
}

// changedSince returns the files this run has not read whose change time is
// after through. A file's owner cannot set its change time back. A file
// without one counts as changed.
func (s *phpContentScan) changedSince(files []string, through time.Time) []string {
	var out []string
	for _, file := range files {
		if _, done := s.attempted[file]; done {
			continue
		}
		info, err := osFS.Stat(file)
		if err != nil {
			continue
		}
		if ctime := phpFileStampOf(info).Ctime; ctime == 0 || time.Unix(0, ctime).After(through) {
			out = append(out, file)
		}
	}
	return out
}

// rotateAfter returns the path-sorted files starting after from, wrapping.
func rotateAfter(files []string, from string) []string {
	if from == "" {
		return files
	}
	i := sort.SearchStrings(files, from)
	if i < len(files) && files[i] == from {
		i++
	}
	return append(append([]string(nil), files[i:]...), files[:i]...)
}

func saveRollingCursor(db *store.DB, cur store.ScanCursorRecord) {
	if err := rollingContentCursors.save(db, cur); err != nil {
		fmt.Fprintf(os.Stderr, "php_content changed pass: cursor write for %s: %v\n", cur.Account, err)
	}
}

func rollingRegularCandidate(file string) bool {
	info, err := osFS.Stat(file)
	return err == nil && info.Mode().IsRegular()
}

// rollingDocRootFor returns the docRoot that contains file. file always sits
// under exactly one of docRoots (enumeratePHPFiles built it by descending from
// them); the longest matching prefix wins so nested account roots resolve to
// the most specific one.
func rollingDocRootFor(file string, docRoots []string) string {
	best := ""
	for _, root := range docRoots {
		if root == file || strings.HasPrefix(file, root+string(filepath.Separator)) {
			if len(root) > len(best) {
				best = root
			}
		}
	}
	return best
}

// enumeratePHPFiles recursively collects, under each docRoot, candidate paths
// whose name contains stock PHP source. This includes source-view .phps files
// without classifying them as executable. The walk is bounded to
// rollingWalkMaxDepth, honours ctx cancellation, and
// respects suppressions.ignore_paths exactly like scanDir when the scan is not
// an explicit full-scan/audit. The result is ascending-sorted and de-duplicated
// so rollingCandidatesAfter can cursor through it stably.
func enumeratePHPFiles(ctx context.Context, cfg *config.Config, docRoots []string) []string {
	seen := make(map[string]struct{})
	respectIgnores := scanRespectsIgnores(ctx, cfg)
	for _, root := range docRoots {
		walkPHPFiles(ctx, cfg, root, rollingWalkMaxDepth, respectIgnores, seen)
		if ctx.Err() != nil {
			break
		}
	}
	if len(seen) == 0 {
		return nil
	}
	files := make([]string, 0, len(seen))
	for f := range seen {
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}

func walkPHPFiles(ctx context.Context, cfg *config.Config, dir string, maxDepth int, respectIgnores bool, seen map[string]struct{}) {
	if ctx.Err() != nil || maxDepth <= 0 {
		return
	}
	entries, err := osFS.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		fullPath := filepath.Join(dir, entry.Name())

		// Same suppression gate as scanDir: this is not a path allowlist for
		// "safe" files but an operator-configured ignore that the periodic scan
		// already honours. It is bypassed for explicit full-scan/audit runs,
		// which never reach rolling anyway (the gate excludes forced runs).
		if respectIgnores && pathIsIgnored(cfg, fullPath) {
			continue
		}

		if entry.IsDir() {
			walkPHPFiles(ctx, cfg, fullPath, maxDepth-1, respectIgnores, seen)
			continue
		}
		if contenttype.IsPHPSourceName(strings.ToLower(entry.Name())) {
			seen[fullPath] = struct{}{}
		}
	}
}

func pathIsIgnored(cfg *config.Config, fullPath string) bool {
	for _, ignore := range cfg.Suppressions.IgnorePaths {
		if matchGlob(fullPath, ignore) {
			return true
		}
	}
	return false
}

// reconstructOverlay builds the handler overlay for fileDir by merging the
// .htaccess files from rootDir down through each ancestor to fileDir, starting
// from an empty overlay at rootDir. This matches how scanDir accumulates
// overlays as it descends. fileDir must be rootDir or a descendant; if rootDir
// is empty (file resolved to no docRoot, which should not happen) the overlay
// is built from fileDir alone.
func reconstructOverlay(rootDir, fileDir string) phpHandlerOverlay {
	overlay := phpHandlerOverlay{}
	if rootDir == "" {
		if data, ok, err := readHtaccessBounded(filepath.Join(fileDir, ".htaccess")); err == nil && ok {
			overlay = overlay.mergeHtaccess(data)
		} else if htaccessOversized(ok, err) {
			overlay.unrestricted = true
		}
		return overlay
	}

	// Build the ordered list of directories from rootDir down to fileDir
	// inclusive by stripping the shared prefix and walking the relative
	// components back on.
	dirs := []string{rootDir}
	rel, err := filepath.Rel(rootDir, fileDir)
	if err == nil && rel != "." && rel != "" && !strings.HasPrefix(rel, "..") {
		cur := rootDir
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			cur = filepath.Join(cur, part)
			dirs = append(dirs, cur)
		}
	}

	for _, d := range dirs {
		if data, ok, err := readHtaccessBounded(filepath.Join(d, ".htaccess")); err == nil && ok {
			overlay = overlay.mergeHtaccess(data)
		} else if htaccessOversized(ok, err) {
			// Unreadable handler configuration: scan every name rather
			// than assume the default extension set.
			overlay.unrestricted = true
		}
	}
	return overlay
}
