package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// fileIndexScanCount tracks the number of CheckFileIndex invocations.
// Every 6th scan forces a full directory rescan, bypassing the mtime cache
// to catch writes that don't update parent directory mtime (e.g. hard links).
var fileIndexScanCount int32

// fileIndexShrinkSkips counts consecutive scans whose current index shrank far
// enough to trip the mass-deletion guard. It self-heals the guard: after
// fileIndexShrinkPromoteThreshold consecutive shrinking scans the smaller index
// is promoted as the new baseline, so new-file detection resumes instead of
// forever diffing against a stale, permanently-larger previous index.
// The live CheckFileIndex path is serialized by fileIndexLiveScanGate, so this
// counter advances once per completed stateful index build rather than racing
// between a periodic deep scan and an operator-triggered tier run.
var fileIndexShrinkSkips int32

// fileIndexLiveScanGate serializes the stateful CheckFileIndex path. The
// scanner reads and writes fileindex.current, fileindex.previous, dircache.json,
// and the shrink streak as one logical baseline update; overlapping live runs
// can otherwise double-count one shrink window or compare against a half-written
// peer scan. ForceFileIndex audit scans return before this gate because they do
// not touch live baseline state.
var fileIndexLiveScanGate = make(chan struct{}, 1)

// fileIndexShrinkPromoteThreshold is how many consecutive shrinking scans must
// occur before the smaller index becomes the baseline. Three deep cycles is
// long enough to rule out a one-off read glitch or a transient mass rename,
// while still healing the wedge automatically within a few scan intervals so no
// operator has to delete fileindex.previous by hand.
const fileIndexShrinkPromoteThreshold = 3

// evaluateFileIndexShrink classifies the current-vs-previous index sizes and
// advances the consecutive-shrink counter. isShrink reports whether this scan
// tripped the mass-deletion guard (an empty current against a populated
// previous, or a non-empty current below half the previous). promote reports
// whether the shrink has now persisted for fileIndexShrinkPromoteThreshold
// consecutive scans, in which case the caller must adopt the smaller index as
// the baseline. Empty current indexes are never promoted: a persistent read
// failure has the same shape, and adopting it would make recovery alert on
// every indexed file as if the whole host were new.
// A non-shrink scan resets the streak so only *consecutive* shrinks promote.
func evaluateFileIndexShrink(prevLen, curLen int) (isShrink, promote bool) {
	if prevLen > 10 && curLen == 0 {
		atomic.StoreInt32(&fileIndexShrinkSkips, 0)
		return true, false
	}
	isShrink = prevLen > 0 && curLen > 0 && curLen*2 < prevLen
	if !isShrink {
		atomic.StoreInt32(&fileIndexShrinkSkips, 0)
		return false, false
	}
	if atomic.AddInt32(&fileIndexShrinkSkips, 1) >= fileIndexShrinkPromoteThreshold {
		atomic.StoreInt32(&fileIndexShrinkSkips, 0)
		return true, true
	}
	return true, false
}

func acquireFileIndexLiveScan(ctx context.Context) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return false
	}
	select {
	case fileIndexLiveScanGate <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func releaseFileIndexLiveScan() {
	<-fileIndexLiveScanGate
}

// suspiciousExtensions are file extensions that should never appear in web roots.
var suspiciousExtensions = map[string]bool{
	".phtml": true, ".pht": true, ".php5": true,
	".haxor": true, ".cgix": true,
}

// dirMtimeCache maps directory paths to their last-known mtime (unix seconds).
// Directories with unchanged mtime are skipped during scanning.
type dirMtimeCache map[string]int64

func loadDirCache(stateDir string) dirMtimeCache {
	cache := make(dirMtimeCache)
	data, err := osFS.ReadFile(filepath.Join(stateDir, "dircache.json"))
	if err == nil {
		_ = json.Unmarshal(data, &cache)
	}
	return cache
}

func saveDirCache(stateDir string, cache dirMtimeCache) {
	data, _ := json.Marshal(cache)
	tmpPath := filepath.Join(stateDir, "dircache.json.tmp")
	_ = os.WriteFile(tmpPath, data, 0600)
	_ = os.Rename(tmpPath, filepath.Join(stateDir, "dircache.json"))
}

// dirChanged returns true if the directory mtime has changed since last scan.
// Updates the cache with the new mtime. If forceFullScan is true, always
// returns true to force a ReadDir regardless of mtime (catches writes that
// bypass parent mtime updates, e.g. hard links or mount tricks).
func dirChanged(dir string, cache dirMtimeCache, forceFullScan bool) bool {
	info, err := osFS.Stat(dir)
	if err != nil {
		return true // can't stat, scan it to be safe
	}
	mtime := info.ModTime().Unix()
	prev, exists := cache[dir]
	cache[dir] = mtime
	if forceFullScan {
		return true
	}
	if !exists {
		return true // first time seeing this dir
	}
	return mtime != prev
}

type subtreeChangeTracker struct {
	cache        dirMtimeCache
	changedBelow map[string]struct{}
	built        bool
}

func newSubtreeChangeTracker(cache dirMtimeCache) *subtreeChangeTracker {
	snapshot := make(dirMtimeCache, len(cache))
	for dir, mtime := range cache {
		snapshot[dir] = mtime
	}
	return &subtreeChangeTracker{cache: snapshot}
}

func (t *subtreeChangeTracker) hasChangedDir(ctx context.Context, dir string) bool {
	if t == nil {
		return false
	}
	if !t.built {
		t.build(ctx)
	}
	_, ok := t.changedBelow[dir]
	return ok
}

func (t *subtreeChangeTracker) build(ctx context.Context) {
	t.built = true
	t.changedBelow = make(map[string]struct{})
	for cached, mtime := range t.cache {
		if ctx != nil && ctx.Err() != nil {
			return
		}
		info, err := osFS.Stat(cached)
		if err == nil && info.ModTime().Unix() == mtime {
			continue
		}
		for parent := filepath.Dir(cached); parent != "." && parent != string(filepath.Separator); parent = filepath.Dir(parent) {
			if _, ok := t.cache[parent]; ok {
				t.changedBelow[parent] = struct{}{}
			}
		}
	}
}

// subtreeHasChangedDir reports whether any directory beneath dir that a prior
// scan already cached now has a different mtime, or has become unreadable. It
// only reads -- the cache is left untouched so the follow-up rescan still
// observes each change through dirChanged.
//
// A file written deep in the tree bumps only its immediate parent's mtime, not
// the mtimes of the directories above it. Without this check a scan that finds
// the top directory unchanged would carry the whole subtree forward from the
// previous index and never notice the new file until the periodic forced full
// scan. Checking every cached descendant closes that window.
func subtreeHasChangedDir(dir string, cache dirMtimeCache) bool {
	return newSubtreeChangeTracker(cache).hasChangedDir(context.Background(), dir)
}

// CheckFileIndex builds an index of suspicious files using pure Go directory
// reads, diffs against the previous index, and alerts on new files.
// Uses directory mtime caching: unchanged dirs carry forward previous entries
// without calling ReadDir, while changed dirs are re-scanned.
//
// When ctx carries AccountScanOptions with ForceFileIndex=true the function
// runs in audit mode: it enumerates only the in-scope account, bypasses the
// directory mtime cache entirely, and writes none of the live state files
// (fileindex.current, fileindex.previous, dircache.json). The normal incremental
// baseline is left byte-for-byte intact. All indexed files are treated as new
// so the caller receives findings for the full current state of the account.
func CheckFileIndex(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}

	// Audit mode: enumerate only the in-scope account, bypass all state I/O.
	// CRITICAL: none of fileindex.current, fileindex.previous, or dircache.json
	// may be written -- corrupting them would silently break future incremental
	// scans by shifting their baseline.
	if scanForceFileIndex(ctx) {
		// Fresh empty cache so every directory is treated as changed.
		auditCache := make(dirMtimeCache)
		// Empty prevByDir so every indexed file is diff'd as new.
		currentEntries := buildFileIndex(ctx, auditCache, nil, true)
		if ctx.Err() != nil {
			return nil
		}
		// All entries are "new" -- diff against empty previous set.
		return checkFileIndexAnalyzeNewFiles(ctx, cfg, currentEntries)
	}

	if !acquireFileIndexLiveScan(ctx) {
		return nil
	}
	defer releaseFileIndexLiveScan()

	scanNum := atomic.AddInt32(&fileIndexScanCount, 1)
	forceFullScan := scanNum%6 == 0 // full rescan every 6th cycle

	indexDir := cfg.StatePath
	currentPath := filepath.Join(indexDir, "fileindex.current")
	previousPath := filepath.Join(indexDir, "fileindex.previous")

	// Load caches
	dirCache := loadDirCache(indexDir)

	// Build a set of previous entries grouped by directory ancestry, so
	// unchanged dirs can carry forward their whole subtree without ReadDir.
	previousEntries := loadIndex(previousPath)
	prevByDir := groupEntriesByUploadDir(previousEntries)

	// Build current index
	currentEntries := buildFileIndex(ctx, dirCache, prevByDir, forceFullScan)

	// A cancelled scan produced a partial index. Do not write or promote it:
	// the partial set or its mtimes would make the next scan compare against
	// stale cache state instead of the last complete baseline.
	if ctx.Err() != nil {
		return nil
	}

	// Save updated dir cache
	saveDirCache(indexDir, dirCache)

	// Write current index (atomic)
	writeIndex(currentPath, currentEntries)

	// First run - save baseline
	if _, err := osFS.Stat(previousPath); os.IsNotExist(err) {
		copyFile(currentPath, previousPath)
		return nil
	}

	prevSet := make(map[string]bool, len(previousEntries))
	for _, e := range previousEntries {
		prevSet[e] = true
	}

	var newFiles []string
	for _, e := range currentEntries {
		if !prevSet[e] {
			newFiles = append(newFiles, e)
		}
	}

	// A large shrink (mass deletion, a WP install removed, or a transient read
	// failure) must not instantly flush the baseline: promoting an empty or
	// much-smaller index would make every surviving file look "new" next cycle
	// and flood alerts. Still, entries that are present in the shrunken current
	// index but absent from the old baseline are genuinely new and must be
	// classified now. Non-promoting shrink cycles merge those paths into the old
	// baseline so they do not alert repeatedly while the deletion guard is still
	// preserving the removed paths against recovery floods.
	if isShrink, promote := evaluateFileIndexShrink(len(previousEntries), len(currentEntries)); isShrink {
		findings := checkFileIndexAnalyzeNewFiles(ctx, cfg, newFiles)
		if promote {
			fmt.Fprintf(os.Stderr, "file_index: shrink persisted %d scans; adopting smaller index (%d entries, was %d) as new baseline\n",
				fileIndexShrinkPromoteThreshold, len(currentEntries), len(previousEntries))
			copyFile(currentPath, previousPath)
		} else {
			if len(newFiles) > 0 {
				writeIndex(previousPath, mergeIndexEntries(previousEntries, newFiles))
			}
			fmt.Fprintf(os.Stderr, "file_index: current index (%d) shrank vs previous (%d); preserving prior baseline this cycle\n",
				len(currentEntries), len(previousEntries))
		}
		return findings
	}

	findings := checkFileIndexAnalyzeNewFiles(ctx, cfg, newFiles)
	copyFile(currentPath, previousPath)
	return findings
}

func mergeIndexEntries(base, extra []string) []string {
	seen := make(map[string]bool, len(base)+len(extra))
	merged := make([]string, 0, len(base)+len(extra))
	for _, e := range base {
		if seen[e] {
			continue
		}
		seen[e] = true
		merged = append(merged, e)
	}
	for _, e := range extra {
		if seen[e] {
			continue
		}
		seen[e] = true
		merged = append(merged, e)
	}
	sort.Strings(merged)
	return merged
}

// checkFileIndexAnalyzeNewFiles classifies a list of newly-detected file paths
// and returns alert.Finding values for those that match known threat patterns.
// Called by both the normal incremental path and the audit (ForceFileIndex) path.
func checkFileIndexAnalyzeNewFiles(ctx context.Context, cfg *config.Config, newFiles []string) []alert.Finding {
	var findings []alert.Finding
	for _, path := range newFiles {
		name := filepath.Base(path)
		nameLower := strings.ToLower(name)

		// Bypassed for explicit full-scan / audit requests.
		suppressed := false
		if scanRespectsIgnores(ctx, cfg) {
			for _, ignore := range cfg.Suppressions.IgnorePaths {
				if matchGlob(path, ignore) {
					suppressed = true
					break
				}
			}
		}
		if suppressed {
			continue
		}

		severity := alert.Severity(-1)
		check := ""
		message := ""
		contentSHA256 := ""

		if strings.Contains(path, "/wp-content/uploads/") && phpPathExecutes(path, nameLower) {
			// Content decides, never the path or name. A negative
			// severity is a content-verified inert stub (e.g. the
			// WordPress "silence is golden" index.php, or BackWPup's
			// "<?php //<json>" working files) and is suppressed; any
			// real code surfaces, malicious or merely present.
			if sev, ck, msg, hash := classifyUploadPHPWithFingerprint(path); sev >= 0 {
				severity = sev
				check = ck
				message = msg
				contentSHA256 = hash
			} else {
				continue
			}
		}

		// PHP files in wp-content/languages and wp-content/upgrade: content-first.
		// Path-only Critical buried real alerts under location noise (WPML
		// translation queues, WP auto-update staging). See classifySensitiveDirPHP.
		if sev, ck, msg, hash := classifySensitiveDirPHPWithFingerprint(path, name); sev >= 0 {
			severity = sev
			check = ck
			message = msg
			contentSHA256 = hash
		}

		if strings.Contains(path, "/.config/") {
			severity = alert.Critical
			check = "new_executable_in_config"
			message = fmt.Sprintf("New executable in .config: %s", path)
		}

		if isWebshellName(nameLower) {
			severity = alert.Critical
			check = "new_webshell_file"
			message = fmt.Sprintf("New file with webshell name: %s", path)
		}

		if isExecutablePHPName(nameLower) && isSuspiciousPHPName(nameLower) {
			if severity < 0 {
				severity = alert.High
				check = "new_suspicious_php"
				message = fmt.Sprintf("New suspicious PHP file: %s", path)
			}
		}

		if severity >= 0 {
			details := ""
			if info, err := osFS.Stat(path); err == nil {
				details = fmt.Sprintf("Size: %d, Mtime: %s", info.Size(), info.ModTime().Format("2006-01-02 15:04:05"))
			}
			f := alert.Finding{
				Severity: severity,
				Check:    check,
				Message:  message,
				Details:  details,
				FilePath: path,
			}
			if IsContentReverifiable(f.Check) {
				f.ContentSHA256 = contentSHA256
				f.DetectLogic = ContentDetectionVersion()
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// classifySensitiveDirPHP returns (severity, check, message) for a PHP file
// in /wp-content/languages/ or /wp-content/upgrade/. Returns a negative
// severity when the path is not in a sensitive dir.
//
// Every PHP file in a sensitive dir is content-analysed -- there is no
// filename allowlist, so an attacker cannot hide a backdoor by naming it like
// a translation or index file. A real indicator keeps Critical severity and
// the content-based check name (obfuscated_php / suspicious_php_content, both
// already wired into autoresponse, remediate, correlation, and attackdb). A
// clean file is demoted to Warning with check new_php_in_sensitive_dir_clean,
// which is intentionally NOT in any of those maps -- a clean file is a
// visibility signal, not an attack. Mirrors the realtime path at fanotify.go.
func classifySensitiveDirPHP(path, name string) (alert.Severity, string, string) {
	sev, check, message, _ := classifySensitiveDirPHPWithFingerprint(path, name)
	return sev, check, message
}

func classifySensitiveDirPHPWithFingerprint(path, name string) (alert.Severity, string, string, string) {
	nameLower := strings.ToLower(name)
	if !phpPathExecutes(path, nameLower) {
		return -1, "", "", ""
	}
	isLanguages := strings.Contains(path, "/wp-content/languages/")
	isUpgrade := strings.Contains(path, "/wp-content/upgrade/")
	if !isLanguages && !isUpgrade {
		return -1, "", "", ""
	}
	locLabel := "wp-content/languages"
	if isUpgrade {
		locLabel = "wp-content/upgrade"
	}
	result, contentSHA256 := analyzePHPContentWithFingerprint(path)
	if result.severity >= 0 {
		return result.severity, result.check, fmt.Sprintf("%s: %s", result.message, path), contentSHA256
	}
	// Fail closed: an unreadable body (attacker racing the scanner with rm or
	// chmod 000) must not be demoted to a clean Warning. Mirrors classifyUploadPHP.
	if !result.readOK {
		return alert.High, "new_php_in_sensitive_dir",
			fmt.Sprintf("New unreadable PHP file in %s: %s", locLabel, path), ""
	}
	if result.empty {
		return alert.High, "new_php_in_sensitive_dir",
			fmt.Sprintf("New empty PHP file in %s: %s", locLabel, path), ""
	}
	// Content-verified inert stub (e.g. the "silence is golden" index.php) is
	// suppressed; any real code surfaces as a non-actionable visibility Warning.
	if IsBenignPHPStub(path) {
		return -1, "", "", ""
	}
	// WordPress 6.5+ auto-generates *.l10n.php translation caches as pure data
	// return arrays. Recognized by content structure (not filename), they carry
	// no executable construct, so suppress rather than warn on every locale file.
	if isWPTranslationCache(path) {
		return -1, "", "", ""
	}
	return alert.Warning, "new_php_in_sensitive_dir_clean",
		fmt.Sprintf("New PHP file in %s (content clean): %s", locLabel, path), ""
}

// groupEntriesByUploadDir groups index entries by each ancestor directory.
// Used to carry forward the whole cached subtree when an unchanged directory
// is skipped before walking into its children.
func groupEntriesByUploadDir(entries []string) map[string][]string {
	grouped := make(map[string][]string)
	for _, path := range entries {
		for dir := filepath.Dir(path); dir != "." && dir != string(filepath.Separator); dir = filepath.Dir(dir) {
			grouped[dir] = append(grouped[dir], path)
		}
	}
	return grouped
}

// buildFileIndex scans targeted directory subtrees using ReadDir.
// Skips directories whose mtime hasn't changed - carries forward
// their entries from the previous index instead.
// If forceFullScan is true, all directories are re-scanned regardless of mtime.
func buildFileIndex(ctx context.Context, dirCache dirMtimeCache, prevByDir map[string][]string, forceFullScan bool) []string {
	var entries []string
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nil
	}

	homeDirs, err := GetScanHomeDirs(ctx)
	if err != nil {
		return nil
	}

	var subtreeChanges *subtreeChangeTracker
	if !forceFullScan {
		subtreeChanges = newSubtreeChangeTracker(dirCache)
	}

	for _, homeEntry := range homeDirs {
		// A cancelled scan must stop walking and let the caller discard the
		// partial index rather than promote it as the new baseline.
		if ctx.Err() != nil {
			return entries
		}
		if !homeEntry.IsDir() {
			continue
		}
		user := homeEntry.Name()
		homeDir := filepath.Join("/home", user)

		// Scan wp-content/uploads for PHP files
		uploadDirs := []string{
			filepath.Join(homeDir, "public_html", "wp-content", "uploads"),
		}
		// Scan directories that shouldn't normally contain user PHP:
		// languages (translation files only), upgrade (temp dir), mu-plugins
		sensitiveWPDirs := []string{
			filepath.Join(homeDir, "public_html", "wp-content", "languages"),
			filepath.Join(homeDir, "public_html", "wp-content", "upgrade"),
			filepath.Join(homeDir, "public_html", "wp-content", "mu-plugins"),
		}
		subDirs, _ := osFS.ReadDir(homeDir)
		for _, sd := range subDirs {
			if ctx.Err() != nil {
				return entries
			}
			if sd.IsDir() && sd.Name() != "public_html" && sd.Name() != "mail" &&
				!strings.HasPrefix(sd.Name(), ".") && sd.Name() != "etc" &&
				sd.Name() != "logs" && sd.Name() != "ssl" && sd.Name() != "tmp" {
				uploadsPath := filepath.Join(homeDir, sd.Name(), "wp-content", "uploads")
				if info, err := osFS.Stat(uploadsPath); err == nil && info.IsDir() {
					uploadDirs = append(uploadDirs, uploadsPath)
				}
				// Also track sensitive dirs for addon domains
				for _, subDir := range []string{"languages", "upgrade", "mu-plugins"} {
					if ctx.Err() != nil {
						return entries
					}
					sensitiveDir := filepath.Join(homeDir, sd.Name(), "wp-content", subDir)
					if info, err := osFS.Stat(sensitiveDir); err == nil && info.IsDir() {
						sensitiveWPDirs = append(sensitiveWPDirs, sensitiveDir)
					}
				}
			}
		}

		for _, uploadsDir := range uploadDirs {
			if ctx.Err() != nil {
				return entries
			}
			scanDirForPHPContextWithTracker(ctx, uploadsDir, 6, dirCache, prevByDir, forceFullScan, phpHandlerOverlay{}, subtreeChanges, &entries)
		}

		// Scan sensitive WP directories for any PHP files
		for _, sensitiveDir := range sensitiveWPDirs {
			if ctx.Err() != nil {
				return entries
			}
			scanDirForPHPContextWithTracker(ctx, sensitiveDir, 4, dirCache, prevByDir, forceFullScan, phpHandlerOverlay{}, subtreeChanges, &entries)
		}

		// Scan .config for executables
		configDir := filepath.Join(homeDir, ".config")
		if ctx.Err() != nil {
			return entries
		}
		scanDirForExecutablesContextWithTracker(ctx, configDir, 3, dirCache, prevByDir, forceFullScan, subtreeChanges, &entries)
	}

	if AccountFromContext(ctx) == "" {
		// Scan tmp dirs
		for _, tmpDir := range []string{"/tmp", "/dev/shm", "/var/tmp"} {
			if ctx.Err() != nil {
				return entries
			}
			scanDirForSuspiciousExtContextWithTracker(ctx, tmpDir, 2, dirCache, prevByDir, forceFullScan, subtreeChanges, &entries)
		}
	}

	sort.Strings(entries)
	return entries
}

// scanDirForPHP recursively reads directories for PHP-executable files.
// If directory mtime is unchanged, carries forward previous entries.
func scanDirForPHP(dir string, maxDepth int, cache dirMtimeCache, prev map[string][]string, forceFullScan bool, overlay phpHandlerOverlay, entries *[]string) {
	scanDirForPHPContext(context.Background(), dir, maxDepth, cache, prev, forceFullScan, overlay, entries)
}

func scanDirForPHPContext(ctx context.Context, dir string, maxDepth int, cache dirMtimeCache, prev map[string][]string, forceFullScan bool, overlay phpHandlerOverlay, entries *[]string) {
	var subtreeChanges *subtreeChangeTracker
	if !forceFullScan {
		subtreeChanges = newSubtreeChangeTracker(cache)
	}
	scanDirForPHPContextWithTracker(ctx, dir, maxDepth, cache, prev, forceFullScan, overlay, subtreeChanges, entries)
}

func scanDirForPHPContextWithTracker(ctx context.Context, dir string, maxDepth int, cache dirMtimeCache, prev map[string][]string, forceFullScan bool, overlay phpHandlerOverlay, subtreeChanges *subtreeChangeTracker, entries *[]string) {
	if maxDepth <= 0 || ctx.Err() != nil {
		return
	}

	if htaccess, err := osFS.ReadFile(filepath.Join(dir, ".htaccess")); err == nil {
		overlay = overlay.mergeHtaccess(htaccess)
	}
	if ctx.Err() != nil {
		return
	}

	changed := dirChanged(dir, cache, forceFullScan || overlay.active())
	if ctx.Err() != nil {
		return
	}
	subtreeChanged := false
	if !changed {
		subtreeChanged = subtreeChanges.hasChangedDir(ctx, dir)
	}
	if ctx.Err() != nil {
		return
	}
	if !changed && !subtreeChanged {
		// dir's mtime is unchanged and no cached subdirectory changed, so the
		// whole subtree is stable: carry the previous entries forward without
		// re-reading disk.
		*entries = append(*entries, prev[dir]...)
		return
	}
	// Either dir changed, or a file was dropped deep in the subtree (bumping
	// only a subdirectory's mtime). Walk it so the new file is indexed now
	// instead of hiding until the periodic forced full scan.

	dirEntries, err := osFS.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range dirEntries {
		if ctx.Err() != nil {
			return
		}
		name := entry.Name()
		fullPath := filepath.Join(dir, name)

		if entry.IsDir() {
			scanDirForPHPContextWithTracker(ctx, fullPath, maxDepth-1, cache, prev, forceFullScan, overlay, subtreeChanges, entries)
			continue
		}

		nameLower := strings.ToLower(name)
		// index.php is indexed too: a webshell named index.php must not hide
		// behind the WordPress silence-stub convention. The inert stub itself
		// is suppressed later by content analysis. All PHP-executable
		// extensions are indexed, not just .php, so a .phtml/.php7 backdoor
		// cannot dodge the index by extension. The two predicates overlap
		// (the PHP family is also "suspicious"), so index each file once.
		if overlay.executes(nameLower) || suspiciousExtensions[filepath.Ext(nameLower)] {
			*entries = append(*entries, fullPath)
		}
	}
}

// scanDirForExecutables reads .config dirs for executable files.
func scanDirForExecutables(dir string, maxDepth int, cache dirMtimeCache, prev map[string][]string, forceFullScan bool, entries *[]string) {
	scanDirForExecutablesContext(context.Background(), dir, maxDepth, cache, prev, forceFullScan, entries)
}

func scanDirForExecutablesContext(ctx context.Context, dir string, maxDepth int, cache dirMtimeCache, prev map[string][]string, forceFullScan bool, entries *[]string) {
	var subtreeChanges *subtreeChangeTracker
	if !forceFullScan {
		subtreeChanges = newSubtreeChangeTracker(cache)
	}
	scanDirForExecutablesContextWithTracker(ctx, dir, maxDepth, cache, prev, forceFullScan, subtreeChanges, entries)
}

func scanDirForExecutablesContextWithTracker(ctx context.Context, dir string, maxDepth int, cache dirMtimeCache, prev map[string][]string, forceFullScan bool, subtreeChanges *subtreeChangeTracker, entries *[]string) {
	if maxDepth <= 0 || ctx.Err() != nil {
		return
	}
	changed := dirChanged(dir, cache, forceFullScan)
	if ctx.Err() != nil {
		return
	}
	subtreeChanged := false
	if !changed {
		subtreeChanged = subtreeChanges.hasChangedDir(ctx, dir)
	}
	if ctx.Err() != nil {
		return
	}
	if !changed && !subtreeChanged {
		*entries = append(*entries, prev[dir]...)
		return
	}

	dirEntries, err := osFS.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range dirEntries {
		if ctx.Err() != nil {
			return
		}
		fullPath := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			scanDirForExecutablesContextWithTracker(ctx, fullPath, maxDepth-1, cache, prev, forceFullScan, subtreeChanges, entries)
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.Mode()&0111 != 0 {
			*entries = append(*entries, fullPath)
		}
	}
}

// scanDirForSuspiciousExt reads tmp dirs for files with suspicious extensions.
func scanDirForSuspiciousExt(dir string, maxDepth int, cache dirMtimeCache, prev map[string][]string, forceFullScan bool, entries *[]string) {
	scanDirForSuspiciousExtContext(context.Background(), dir, maxDepth, cache, prev, forceFullScan, entries)
}

func scanDirForSuspiciousExtContext(ctx context.Context, dir string, maxDepth int, cache dirMtimeCache, prev map[string][]string, forceFullScan bool, entries *[]string) {
	var subtreeChanges *subtreeChangeTracker
	if !forceFullScan {
		subtreeChanges = newSubtreeChangeTracker(cache)
	}
	scanDirForSuspiciousExtContextWithTracker(ctx, dir, maxDepth, cache, prev, forceFullScan, subtreeChanges, entries)
}

func scanDirForSuspiciousExtContextWithTracker(ctx context.Context, dir string, maxDepth int, cache dirMtimeCache, prev map[string][]string, forceFullScan bool, subtreeChanges *subtreeChangeTracker, entries *[]string) {
	if maxDepth <= 0 || ctx.Err() != nil {
		return
	}
	changed := dirChanged(dir, cache, forceFullScan)
	if ctx.Err() != nil {
		return
	}
	subtreeChanged := false
	if !changed {
		subtreeChanged = subtreeChanges.hasChangedDir(ctx, dir)
	}
	if ctx.Err() != nil {
		return
	}
	if !changed && !subtreeChanged {
		*entries = append(*entries, prev[dir]...)
		return
	}

	dirEntries, err := osFS.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range dirEntries {
		if ctx.Err() != nil {
			return
		}
		name := entry.Name()
		fullPath := filepath.Join(dir, name)
		if entry.IsDir() {
			scanDirForSuspiciousExtContextWithTracker(ctx, fullPath, maxDepth-1, cache, prev, forceFullScan, subtreeChanges, entries)
			continue
		}
		ext := filepath.Ext(strings.ToLower(name))
		if suspiciousExtensions[ext] {
			*entries = append(*entries, fullPath)
		}
	}
}

func isWebshellName(name string) bool {
	webshells := map[string]bool{
		"h4x0r.php": true, "c99.php": true, "r57.php": true,
		"wso.php": true, "alfa.php": true, "b374k.php": true,
		"shell.php": true, "cmd.php": true, "backdoor.php": true,
		"webshell.php": true, "hack.php": true, "0x.php": true,
		"up.php": true, "uploader.php": true, "filemanager.php": true,
	}
	return webshells[name]
}

func isSuspiciousPHPName(name string) bool {
	suspicious := []string{
		"shell", "cmd", "exec", "hack", "backdoor", "upload",
		"exploit", "reverse", "connect", "proxy", "tunnel",
		"0x", "x0", "eval", "assert", "passthru",
	}
	for _, s := range suspicious {
		if strings.Contains(name, s) {
			return true
		}
	}
	nameNoExt := strings.TrimSuffix(name, ".php")
	if len(nameNoExt) <= 5 && strings.ContainsAny(nameNoExt, "0123456789") {
		return true
	}
	return false
}

func writeIndex(path string, entries []string) {
	tmpPath := path + ".tmp"
	// #nosec G304 -- path is filepath.Join under operator-configured StatePath.
	f, err := os.Create(tmpPath)
	if err != nil {
		return
	}

	w := bufio.NewWriter(f)
	for _, e := range entries {
		_, _ = w.WriteString(e + "\n")
	}
	_ = w.Flush()
	_ = f.Close()
	_ = os.Rename(tmpPath, path)
}

func loadIndex(path string) []string {
	f, err := osFS.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var entries []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			entries = append(entries, line)
		}
	}
	return entries
}

func copyFile(src, dst string) {
	data, err := osFS.ReadFile(src)
	if err != nil {
		return
	}
	_ = os.WriteFile(dst, data, 0600)
}
