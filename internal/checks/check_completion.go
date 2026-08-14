package checks

import (
	"context"
	"sync"
)

type incompleteCheckCollector struct {
	mu    sync.Mutex
	names map[string]struct{}
}

type incompleteCheckContextKey struct{}

func withIncompleteCheckCollector(ctx context.Context) (context.Context, *incompleteCheckCollector) {
	collector := &incompleteCheckCollector{names: make(map[string]struct{})}
	return context.WithValue(ctx, incompleteCheckContextKey{}, collector), collector
}

func markCheckIncomplete(ctx context.Context, name string) {
	if ctx == nil {
		return
	}
	collector, _ := ctx.Value(incompleteCheckContextKey{}).(*incompleteCheckCollector)
	if collector == nil {
		return
	}
	collector.mu.Lock()
	collector.names[name] = struct{}{}
	collector.mu.Unlock()
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
