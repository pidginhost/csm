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
	collector, _ := ctx.Value(incompleteCheckContextKey{}).(*incompleteCheckCollector)
	if collector == nil {
		return
	}
	collector.mu.Lock()
	collector.names[name] = struct{}{}
	collector.mu.Unlock()
}

func (c *incompleteCheckCollector) contains(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.names[name]
	return ok
}
