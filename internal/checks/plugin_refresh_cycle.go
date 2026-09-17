package checks

import (
	"context"
	"sync"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

type wpInventoryCycle struct {
	mu    sync.Mutex
	calls map[*store.DB]*wpInventoryCycleCall
}

type wpInventoryCycleCall struct {
	done  chan struct{}
	fresh bool
}

// ensurePluginCacheFresh reuses one refresh result for all consumers in a
// scan, even if the first consumer has finished before the next one starts.
func ensurePluginCacheFresh(ctx context.Context, cfg *config.Config, db *store.DB) bool {
	cycle := wpInstallCacheFrom(ctx)
	if cycle == nil {
		return ensurePluginCacheFreshShared(ctx, cfg, db)
	}
	inventory := &cycle.inventory
	inventory.mu.Lock()
	if call := inventory.calls[db]; call != nil {
		inventory.mu.Unlock()
		select {
		case <-call.done:
			return call.fresh
		case <-ctx.Done():
			return false
		}
	}
	call := &wpInventoryCycleCall{done: make(chan struct{})}
	if inventory.calls == nil {
		inventory.calls = make(map[*store.DB]*wpInventoryCycleCall)
	}
	inventory.calls[db] = call
	inventory.mu.Unlock()
	defer close(call.done)
	call.fresh = ensurePluginCacheFreshShared(ctx, cfg, db)
	return call.fresh
}
