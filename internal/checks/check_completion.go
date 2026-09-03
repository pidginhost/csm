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

// CoverageGaps exposes the files a scan walked but could not examine, so the
// caller that persists the scan's findings can keep those findings rather than
// purging them. The scan itself does not know how its results are stored.
type CoverageGaps struct{ collector *incompleteCheckCollector }

// Paths returns every file this scan could not examine, across all owners.
func (g *CoverageGaps) Paths() map[string]bool {
	if g == nil || g.collector == nil {
		return nil
	}
	g.collector.mu.Lock()
	defer g.collector.mu.Unlock()
	out := make(map[string]bool)
	for owner, paths := range g.collector.paths {
		if _, unattributed := g.collector.unattributed[owner]; unattributed {
			// The owner has a gap it could not pin to a file, so it purges
			// nothing this cycle and its per-file gaps are moot.
			continue
		}
		for path := range paths {
			out[path] = true
		}
	}
	return out
}

// WithCoverageGaps gives the caller ownership of the collector a scan fills in,
// so it can read the coverage gaps after the scan returns without widening
// every runner signature.
func WithCoverageGaps(ctx context.Context) (context.Context, *CoverageGaps) {
	ctx, collector := withIncompleteCheckCollector(ctx)
	return ctx, &CoverageGaps{collector: collector}
}

func withIncompleteCheckCollector(ctx context.Context) (context.Context, *incompleteCheckCollector) {
	// Reuse a collector the caller already installed, so it can read the gaps
	// the scan records.
	if existing := incompleteCollectorFrom(ctx); existing != nil {
		return ctx, existing
	}
	collector := &incompleteCheckCollector{
		names:        make(map[string]struct{}),
		paths:        make(map[string]map[string]bool),
		unattributed: make(map[string]struct{}),
	}
	return context.WithValue(ctx, incompleteCheckContextKey{}, collector), collector
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
