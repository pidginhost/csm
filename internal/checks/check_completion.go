package checks

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

// incompleteCheckCollector records owners whose coverage this run could not
// complete. Known file gaps can be preserved in the eventual store transaction;
// an unknown range prevents the owner from retiring anything.
type incompleteCheckCollector struct {
	mu      sync.Mutex
	names   map[string]struct{}
	skipped map[string]bool
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

// markCheckSkipped preserves both discovered state and the last run's coverage
// summary when an internal refresh interval prevents any new audit work.
func markCheckSkipped(ctx context.Context, name string) {
	collector := incompleteCollectorFrom(ctx)
	if collector == nil {
		return
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.names[name] = struct{}{}
	if collector.skipped == nil {
		collector.skipped = make(map[string]bool)
	}
	collector.skipped[name] = true
}

func (c *incompleteCheckCollector) wasSkipped(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.skipped[name]
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

// gapPathSet is the bookkeeping the deep-scan gap collectors share: the exact
// paths a run walked but could not examine, a count and one example per
// status, and the ranges the walk could not enumerate at all. Carry-forward
// needs exact paths, so the set is bounded and reports itself incomplete past
// the bound instead of carrying forward an arbitrary prefix.
type gapPathSet struct {
	paths         map[string]struct{}
	pathAliases   map[string]struct{}
	aliasesByPath map[string][]string
	byStatus      map[string]int
	example       map[string]string
	// resolveAliases captures every spelling a finding for the path can use.
	// It reports false when the path changed while its identity was captured.
	resolveAliases func(string) ([]string, bool)
	// unknown counts walk failures whose affected paths cannot be enumerated
	// (an unreadable directory, a failed Lstat that may hide one). They are
	// kept apart from paths because carry-forward needs exact paths, but they
	// must still reach the operator.
	unknown        int
	unknownExample string
	// pathsTruncated records that the exact-path set hit maxPaths, so the
	// carry-forward can no longer be trusted to cover every gapped path.
	pathsTruncated  bool
	maxPaths        int
	exampleMaxBytes int
}

func newGapPathSet(maxPaths, exampleMaxBytes int, resolveAliases func(string) ([]string, bool)) gapPathSet {
	return gapPathSet{
		paths:           map[string]struct{}{},
		pathAliases:     map[string]struct{}{},
		aliasesByPath:   map[string][]string{},
		byStatus:        map[string]int{},
		example:         map[string]string{},
		resolveAliases:  resolveAliases,
		maxPaths:        maxPaths,
		exampleMaxBytes: exampleMaxBytes,
	}
}

// lexicalGapAliases names a path by its absolute lexical spelling only. It is
// the resolver of a collector whose walk supplies no observed aliases.
func lexicalGapAliases(path string) ([]string, bool) {
	return []string{coverageLexicalPath(path)}, true
}

// retain counts path under status and returns the aliases of an
// authoritatively retained path. It returns nil once the set is full, or when
// the path changed while its identity was captured.
func (g *gapPathSet) retain(path, status string) []string {
	aliases, retained := g.aliasesByPath[path]
	if !retained && len(g.paths) >= g.maxPaths {
		// Stop retaining paths, but never stop counting: the count is what
		// tells an operator how much of the host went unexamined.
		g.pathsTruncated = true
	} else if !retained {
		var stable bool
		aliases, stable = g.resolveAliases(path)
		if stable {
			g.paths[path] = struct{}{}
			g.aliasesByPath[path] = aliases
			for _, alias := range aliases {
				g.pathAliases[alias] = struct{}{}
			}
		} else {
			g.recordUnknownRange(fmt.Sprintf("%s changed while its path identity was captured", path))
			aliases = nil
		}
	}
	g.byStatus[status]++
	if _, ok := g.example[status]; !ok {
		g.example[status] = sanitizeJSTaintDisplay(path, g.exampleMaxBytes)
	}
	return aliases
}

// recordUnknownRange notes coverage lost over a range this walk cannot
// enumerate. It deliberately does not add to paths: claiming specific paths
// would be false, and the unknown range already forces a partial run, which
// suppresses the purge for every prior finding.
func (g *gapPathSet) recordUnknownRange(detail string) {
	g.unknown++
	if g.unknownExample == "" {
		g.unknownExample = sanitizeJSTaintDisplay(detail, g.exampleMaxBytes)
	}
}

// pathsIncomplete reports that this run could not enumerate every gapped path,
// either because retention hit its bound or because the walk lost an unknown
// range. Its carry-forward set is therefore not authoritative and the purge
// must be suppressed for the whole owner.
func (g *gapPathSet) pathsIncomplete() bool { return g.pathsTruncated || g.unknown > 0 }

func (g *gapPathSet) empty() bool { return len(g.byStatus) == 0 && g.unknown == 0 }

func (g *gapPathSet) hasPath(path string) bool {
	if _, ok := g.paths[path]; ok {
		return true
	}
	for _, alias := range coveragePathAliases(path) {
		if _, ok := g.pathAliases[alias]; ok {
			return true
		}
	}
	return false
}

// statusParts renders byStatus as one "status=count (example)" part per
// status, in status order, and returns the summed count.
func (g *gapPathSet) statusParts(byStatus map[string]int) (int, []string) {
	total := 0
	statuses := make([]string, 0, len(byStatus))
	for status, n := range byStatus {
		total += n
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	parts := make([]string, 0, len(statuses)+2)
	for _, status := range statuses {
		parts = append(parts, fmt.Sprintf("%s=%d (example: %s)", status, byStatus[status], g.example[status]))
	}
	return total, parts
}

// rangeLossParts renders the facts that make the exact-path set incomplete.
func (g *gapPathSet) rangeLossParts() []string {
	var parts []string
	if g.unknown > 0 {
		parts = append(parts, fmt.Sprintf("unreadable-range=%d (example: %s)", g.unknown, g.unknownExample))
	}
	if g.pathsTruncated {
		parts = append(parts, fmt.Sprintf("exact paths retained for only the first %d", g.maxPaths))
	}
	return parts
}

// incompleteFinding reports every gap in one alert. filesFormat takes the
// file count; rangesFormat takes the lost-range count and is used when no
// file was counted.
func (g *gapPathSet) incompleteFinding(severity alert.Severity, check, filesFormat, rangesFormat string) alert.Finding {
	total, parts := g.statusParts(g.byStatus)
	parts = append(parts, g.rangeLossParts()...)
	message := fmt.Sprintf(filesFormat, total)
	if total == 0 {
		message = fmt.Sprintf(rangesFormat, g.unknown)
	}
	return alert.Finding{
		Severity: severity,
		Check:    check,
		Message:  message,
		Details:  strings.Join(parts, "; "),
		// One host-wide condition: counts and examples vary per cycle and
		// must not re-alert while coverage stays degraded.
		DedupKey: "coverage_gap",
	}
}

// carryForwardLatestPerPath keeps at most one prior finding of check for each
// path the current full cycle could not analyze. Partial rolling windows can
// leave more than one historical variant at a path because their owner is not
// purgeable; the most recently observed variant is the one that represents
// current state when a later full cycle hits a path-specific gap.
func carryForwardLatestPerPath(prior []alert.Finding, check string, gaps *gapPathSet) []alert.Finding {
	byPath := make(map[string]alert.Finding)
	for _, finding := range prior {
		if finding.Check != check || !gaps.hasPath(finding.FilePath) {
			continue
		}
		current, exists := byPath[finding.FilePath]
		if !exists || finding.Timestamp.After(current.Timestamp) ||
			(finding.Timestamp.Equal(current.Timestamp) && finding.Key() < current.Key()) {
			byPath[finding.FilePath] = finding
		}
	}
	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	carried := make([]alert.Finding, 0, len(paths))
	for _, path := range paths {
		finding := byPath[path]
		finding.ScanCarryForward = true
		carried = append(carried, finding)
	}
	return carried
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
