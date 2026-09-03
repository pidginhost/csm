package checks

import (
	"context"
	"sync"
)

type incompleteCheckCollector struct {
	mu sync.Mutex
	// names are owners with a coverage gap this run. paths records, per owner,
	// the specific files the gap is attributable to; an owner whose every gap
	// names a file can still retire findings for the files it did read.
	names map[string]struct{}
	paths map[string]map[string]bool
	// unattributed marks an owner whose gap cannot be pinned to files at all
	// (no rules loaded, a cursor that could not be read). Such an owner says
	// nothing about any file, so none of its findings may be retired.
	unattributed map[string]struct{}
}

type incompleteCheckContextKey struct{}

type coverageGapsContextKey struct{}

// CoverageGaps exposes, by finding name, the files a scan walked but could not
// examine. Scoping paths to the owner prevents one consumer in a shared walk
// from retaining another consumer's findings for the same file.
//
// A handle contains only the most recently completed scan run with its context.
// Reusing that context for a later run replaces the snapshot instead of carrying
// old gaps into the new cycle.
type CoverageGaps struct {
	mu           sync.Mutex
	pathsByCheck map[string]map[string]bool
}

// Paths returns the files this scan could not examine, scoped to the finding
// names whose purge must preserve them.
func (g *CoverageGaps) Paths() map[string]map[string]bool {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return cloneCoverageGapPaths(g.pathsByCheck)
}

// WithCoverageGaps gives the caller a snapshot sink the next runner invocation
// fills in, so it can read the coverage gaps after the scan returns without
// widening every runner signature.
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
	collector := &incompleteCheckCollector{
		names:        make(map[string]struct{}),
		paths:        make(map[string]map[string]bool),
		unattributed: make(map[string]struct{}),
	}
	return context.WithValue(ctx, incompleteCheckContextKey{}, collector), collector
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
// particular files. The owner keeps every finding it has until it completes.
func markCheckIncomplete(ctx context.Context, name string) {
	collector := incompleteCollectorFrom(ctx)
	if collector == nil {
		return
	}
	collector.mu.Lock()
	collector.names[name] = struct{}{}
	collector.unattributed[name] = struct{}{}
	collector.mu.Unlock()
}

// markCheckIncompletePath records a coverage gap for one named file: the scan
// walked it but could not examine it. Findings for that file survive the
// cycle's purge, while findings for files the scan did read are retired
// normally. Without this a single permanently unreadable file -- an error_log
// past the scan limit, say -- froze the whole owner's findings forever.
func markCheckIncompletePath(ctx context.Context, name, path string) {
	collector := incompleteCollectorFrom(ctx)
	if collector == nil || path == "" {
		return
	}
	collector.mu.Lock()
	collector.names[name] = struct{}{}
	if collector.paths[name] == nil {
		collector.paths[name] = make(map[string]bool)
	}
	collector.paths[name][path] = true
	collector.mu.Unlock()
}

func incompleteCollectorFrom(ctx context.Context) *incompleteCheckCollector {
	if ctx == nil {
		return nil
	}
	collector, _ := ctx.Value(incompleteCheckContextKey{}).(*incompleteCheckCollector)
	return collector
}

// attributable reports whether every gap this owner recorded names a file, so
// the owner may purge findings for the files it did cover.
func (c *incompleteCheckCollector) attributable(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.names[name]; !ok {
		return false
	}
	_, unattributed := c.unattributed[name]
	return !unattributed && len(c.paths[name]) > 0
}

// gapPaths returns the files an owner could not examine this run.
func (c *incompleteCheckCollector) gapPaths(name string) map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]bool, len(c.paths[name]))
	for p := range c.paths[name] {
		out[p] = true
	}
	return out
}

func checkMarkedIncomplete(ctx context.Context, name string) bool {
	if ctx == nil {
		return false
	}
	collector, _ := ctx.Value(incompleteCheckContextKey{}).(*incompleteCheckCollector)
	return collector != nil && collector.contains(name)
}

func (c *incompleteCheckCollector) contains(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.names[name]
	return ok
}
