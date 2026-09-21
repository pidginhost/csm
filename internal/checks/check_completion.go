package checks

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"sync"

	"github.com/pidginhost/csm/internal/state"
)

// incompleteCheckCollector records owners whose coverage this run could not
// complete. Known file gaps can be preserved in the eventual store transaction;
// an unknown range prevents the owner from retiring anything.
type incompleteCheckCollector struct {
	mu    sync.Mutex
	names map[string]struct{}
}

type incompleteCheckContextKey struct{}

type coverageGapsContextKey struct{}

type coveragePathCollectorContextKey struct{}

type coveragePathCollector struct {
	mu            sync.Mutex
	pathsByOwner  map[string]map[string]bool
	scopesByOwner map[string]map[string]bool
}

// CoverageGaps holds file gaps and completed database scopes for a scan.
// The caller passes it to the atomic purge-and-merge operation so a concurrent
// update made after the scanner read LatestFindings cannot be retired by a
// stale carry-forward snapshot.
type CoverageGaps struct {
	mu               sync.Mutex
	pathsByCheck     map[string]map[string]bool
	completedScopes  map[string]map[string]bool
	incompleteChecks map[string]bool
}

// Paths returns an isolated snapshot of the completed run's path gaps. Each
// inner key is a stable lexical or resolved alias captured during the scan.
func (g *CoverageGaps) Paths() map[string]map[string]bool {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return cloneCoverageGapPaths(g.pathsByCheck)
}

// WithCoverageGaps requests an atomic coverage-aware store operation from the
// caller. The runner publishes only its completed snapshot into the handle.
func WithCoverageGaps(ctx context.Context) (context.Context, *CoverageGaps) {
	if ctx == nil {
		ctx = context.Background()
	}
	gaps := &CoverageGaps{}
	return context.WithValue(ctx, coverageGapsContextKey{}, gaps), gaps
}

func withIncompleteCheckCollector(ctx context.Context) (context.Context, *incompleteCheckCollector) {
	if ctx == nil {
		ctx = context.Background()
	}
	collector := &incompleteCheckCollector{names: make(map[string]struct{})}
	return context.WithValue(ctx, incompleteCheckContextKey{}, collector), collector
}

func withCoveragePathCollector(ctx context.Context) (context.Context, *coveragePathCollector) {
	collector := &coveragePathCollector{pathsByOwner: make(map[string]map[string]bool)}
	return context.WithValue(ctx, coveragePathCollectorContextKey{}, collector), collector
}

func coverageGapsFrom(ctx context.Context) *CoverageGaps {
	if ctx == nil {
		return nil
	}
	gaps, _ := ctx.Value(coverageGapsContextKey{}).(*CoverageGaps)
	return gaps
}

func (g *CoverageGaps) replace(pathsByCheck map[string]map[string]bool, completedScopes map[string]map[string]bool, incompleteChecks map[string]bool) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.pathsByCheck = cloneCoverageGapPaths(pathsByCheck)
	g.completedScopes = cloneCoverageGapPaths(completedScopes)
	g.incompleteChecks = maps.Clone(incompleteChecks)
	g.mu.Unlock()
}

func cloneCoverageGapPaths(pathsByCheck map[string]map[string]bool) map[string]map[string]bool {
	if len(pathsByCheck) == 0 {
		return nil
	}
	out := make(map[string]map[string]bool, len(pathsByCheck))
	for check, paths := range pathsByCheck {
		if len(paths) == 0 {
			continue
		}
		cloned := make(map[string]bool, len(paths))
		for path := range paths {
			cloned[path] = true
		}
		out[check] = cloned
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// markCheckIncomplete records a coverage gap that cannot be attributed to
// particular files, so the owner keeps every finding it has until it completes.
func markCheckIncomplete(ctx context.Context, name string) {
	collector := incompleteCollectorFrom(ctx)
	if collector == nil {
		return
	}
	collector.mu.Lock()
	collector.names[name] = struct{}{}
	collector.mu.Unlock()
}

// A removed path is covered absence; a failed read is not evidence of cleanup.
func markScanReadError(ctx context.Context, owner string, err error) {
	if err != nil && !os.IsNotExist(err) {
		markCheckIncomplete(ctx, owner)
	}
}

// Unlike the best-effort inventory, partial discovery cannot authorize a
// stateful scanner to retire findings from accounts it never enumerated.
func scanHomeDirsWithCoverage(ctx context.Context, owner string) []os.DirEntry {
	if AccountFromContext(ctx) != "" {
		entries, err := GetScanHomeDirs(ctx)
		markScanReadError(ctx, owner, err)
		return entries
	}
	homes, err := readAccountHomes()
	markScanReadError(ctx, owner, err)
	entries := make([]os.DirEntry, 0, len(homes))
	for _, home := range homes {
		entries = append(entries, rootedDirEntry{DirEntry: home.Entry, root: home.Root})
	}
	return entries
}

// recordCoverageGapPaths records the stable aliases captured when a known file
// gap was observed. The store must consume these aliases as identities, without
// resolving them again after a symlink may have changed targets.
func recordCoverageGapPaths(ctx context.Context, owner string, paths []string) {
	if ctx == nil || len(paths) == 0 {
		return
	}
	collector, _ := ctx.Value(coveragePathCollectorContextKey{}).(*coveragePathCollector)
	if collector == nil {
		return
	}
	collector.mu.Lock()
	if collector.pathsByOwner[owner] == nil {
		collector.pathsByOwner[owner] = make(map[string]bool)
	}
	for _, path := range paths {
		if path != "" {
			collector.pathsByOwner[owner][path] = true
		}
	}
	collector.mu.Unlock()
}

// coveragePathAliases captures every path spelling a Finding.FilePath emitted
// by this walk can use: its absolute lexical form and, while the observed path
// still resolves, its symlink-resolved form. Callers retain the returned set so
// a later symlink retarget cannot change the preservation identity.
func coveragePathAliases(path string) []string {
	lexical := coverageLexicalPath(path)
	if lexical == "" {
		return nil
	}
	aliases := []string{lexical}
	if real, err := filepath.EvalSymlinks(lexical); err == nil {
		real = filepath.Clean(real)
		if real != lexical {
			aliases = append(aliases, real)
		}
	}
	return aliases
}

func coverageLexicalPath(path string) string {
	if path == "" {
		return ""
	}
	lexical := filepath.Clean(path)
	if absolute, err := filepath.Abs(lexical); err == nil {
		lexical = filepath.Clean(absolute)
	}
	return lexical
}

// stableCoveragePathAliases binds aliases to the file metadata that caused the
// scanner's decision. Re-checking both the lexical and resolved paths prevents
// a symlink retarget during alias construction from preserving a different file
// while retiring the one that actually went unexamined.
func stableCoveragePathAliases(path string, expected os.FileInfo) ([]string, bool) {
	aliases := coveragePathAliases(path)
	if expected == nil || len(aliases) == 0 {
		return aliases, false
	}
	lexicalInfo, err := osFS.Lstat(aliases[0])
	if err != nil || lexicalInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(expected, lexicalInfo) {
		return aliases, false
	}
	for _, alias := range aliases[1:] {
		resolvedInfo, statErr := osFS.Stat(alias)
		if statErr != nil || !os.SameFile(expected, resolvedInfo) {
			return aliases, false
		}
	}
	lexicalInfo, err = osFS.Lstat(aliases[0])
	if err != nil || lexicalInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(expected, lexicalInfo) {
		return aliases, false
	}
	return aliases, true
}

func incompleteCollectorFrom(ctx context.Context) *incompleteCheckCollector {
	if ctx == nil {
		return nil
	}
	collector, _ := ctx.Value(incompleteCheckContextKey{}).(*incompleteCheckCollector)
	return collector
}

func checkMarkedIncomplete(ctx context.Context, name string) bool {
	collector := incompleteCollectorFrom(ctx)
	return collector != nil && collector.contains(name)
}

func (c *coveragePathCollector) gapPaths(owner string) map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]bool, len(c.pathsByOwner[owner]))
	for path := range c.pathsByOwner[owner] {
		out[path] = true
	}
	return out
}

func (c *incompleteCheckCollector) contains(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.names[name]
	return ok
}

// Snapshot includes both file gaps and completed database scopes from the same
// runner result. Callers must pass this snapshot to the atomic store operation.
func (g *CoverageGaps) Snapshot() *state.ScanCoverage {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return &state.ScanCoverage{
		PreservePaths:    cloneCoverageGapPaths(g.pathsByCheck),
		CompletedScopes:  cloneCoverageGapPaths(g.completedScopes),
		IncompleteChecks: maps.Clone(g.incompleteChecks),
	}
}

func recordCompletedCoverageScopes(ctx context.Context, owner string, scopes map[string]bool) {
	if ctx == nil {
		return
	}
	collector, _ := ctx.Value(coveragePathCollectorContextKey{}).(*coveragePathCollector)
	if collector == nil {
		return
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.scopesByOwner == nil {
		collector.scopesByOwner = make(map[string]map[string]bool)
	}
	complete := make(map[string]bool)
	for scope, covered := range scopes {
		if covered && scope != "" {
			complete[scope] = true
		}
	}
	collector.scopesByOwner[owner] = complete
}

func (c *coveragePathCollector) completedScopes(owner string) map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]bool, len(c.scopesByOwner[owner]))
	for scope := range c.scopesByOwner[owner] {
		out[scope] = true
	}
	return out
}
