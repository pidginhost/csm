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

// rollingContentCoverage sweeps a bounded path-sorted slice of the account's
// full docroot PHP set, advancing the per-account cursor so every stock-PHP
// file is eventually content-scanned over cycles. The caller guarantees the
// gate (rolling on, host-scope periodic, not a forced/audit run). Findings
// append to the live findings slice (rolling is part of the periodic scan, not
// a report-only full-scan job). A canceled run leaves the prior cursor
// untouched.
//
// Limitation: rolling enumerates only stock-PHP-executable filenames across the
// whole docroot. A file whose non-stock extension is remapped to PHP by an
// .htaccess handler (the LEVIATHAN trick) is NOT enumerated here; the fixed
// suspicious-dir scan (which layers per-directory overlays as it descends) and
// realtime fanotify still cover those.
func rollingContentCoverage(ctx context.Context, cfg *config.Config, scan *phpContentScan, account string, docRoots []string, findings *[]alert.Finding) {
	db := store.Global()
	if db == nil {
		// Cannot persist a cursor, so rolling would scan from the start every
		// cycle without making progress. Skip rather than spin in place.
		return
	}

	files := enumeratePHPFiles(ctx, cfg, docRoots)
	if len(files) == 0 {
		return
	}

	limit := accountScanMaxFiles(ctx, cfg)
	cur, _, curErr := db.GetScanCursor(account, rollingScanCheck)
	if curErr != nil {
		// A persistent read error would re-scan from the start every cycle and
		// never reach dormant files past the cap. Surface it; cur is the zero
		// record so this cycle still scans the head of the list.
		fmt.Fprintf(os.Stderr, "php_content rolling: cursor read for %s: %v\n", account, curErr)
	}
	selected, newLast, wrapped := rollingCandidatesAfter(files, cur.LastPath, limit)
	if len(selected) == 0 {
		return
	}

	// Reconstruct the .htaccess handler overlay once per directory: every file
	// in the slice that shares a directory shares the same overlay, and reading
	// the ancestor .htaccess chain per file would multiply the read cost.
	overlayCache := make(map[string]phpHandlerOverlay)
	for _, file := range selected {
		if ctx.Err() != nil {
			break
		}
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
		return
	}
	cur.Account = account
	cur.Check = rollingScanCheck
	cur.LastPath = newLast
	if wrapped {
		now := time.Now().UTC()
		cur.WrappedAt = now
		cur.LastFullCycleTS = now
	}
	_ = db.PutScanCursor(cur)
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

// enumeratePHPFiles recursively collects, under each docRoot, regular files
// whose name a stock PHP handler executes (empty-overlay executability). The
// walk is bounded to rollingWalkMaxDepth, honours ctx cancellation, and
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
		if (phpHandlerOverlay{}).executes(strings.ToLower(entry.Name())) {
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
		if data, err := osFS.ReadFile(filepath.Join(fileDir, ".htaccess")); err == nil {
			overlay = overlay.mergeHtaccess(data)
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
		if data, err := osFS.ReadFile(filepath.Join(d, ".htaccess")); err == nil {
			overlay = overlay.mergeHtaccess(data)
		}
	}
	return overlay
}
