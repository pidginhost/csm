package checks

import (
	"context"
	"sync"
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
	mu           sync.Mutex
	pathsByOwner map[string]map[string]bool
}

// CoverageGaps is the path-scoped part of a completed scan's coverage result.
// The caller passes it to the atomic purge-and-merge operation so a concurrent
// update made after the scanner read LatestFindings cannot be retired by a
// stale carry-forward snapshot.
type CoverageGaps struct {
	mu           sync.Mutex
	pathsByCheck map[string]map[string]bool
}

// Paths returns an isolated snapshot of the completed run's path gaps.
func (g *CoverageGaps) Paths() map[string]map[string]bool {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return cloneCoverageGapPaths(g.pathsByCheck)
}

// WithCoverageGaps requests an atomic path-preserving store operation from the
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

func (g *CoverageGaps) replace(pathsByCheck map[string]map[string]bool) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.pathsByCheck = cloneCoverageGapPaths(pathsByCheck)
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

// recordCoverageGapPath records a known file gap without marking the owner
// incomplete. The owner may retire covered findings; current findings for this
// path are protected later by the caller's atomic purge-and-merge.
func recordCoverageGapPath(ctx context.Context, owner, path string) {
	if ctx == nil || path == "" {
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
	collector.pathsByOwner[owner][path] = true
	collector.mu.Unlock()
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
