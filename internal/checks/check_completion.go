package checks

import (
	"context"
	"sync"
)

// incompleteCheckCollector records the owners whose coverage this run could not
// complete. A gap that names a file is handled by the consumer that found it,
// which carries that file's prior finding forward; this collector is only for
// gaps that leave an unknown range, where nothing the owner owns may be
// retired.
type incompleteCheckCollector struct {
	mu    sync.Mutex
	names map[string]struct{}
}

type incompleteCheckContextKey struct{}

func withIncompleteCheckCollector(ctx context.Context) (context.Context, *incompleteCheckCollector) {
	if ctx == nil {
		ctx = context.Background()
	}
	collector := &incompleteCheckCollector{names: make(map[string]struct{})}
	return context.WithValue(ctx, incompleteCheckContextKey{}, collector), collector
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

func (c *incompleteCheckCollector) contains(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.names[name]
	return ok
}
