package wpcheck

import (
	"time"
)

// SetStopCh wires a daemon-level cancellation channel into the cache.
// Closing the channel signals every pending checksum-retry timer to drop
// the scheduled fetch instead of firing. Safe to call once after NewCache,
// before any fetches start.
func (c *Cache) SetStopCh(stop <-chan struct{}) {
	c.stopMu.Lock()
	c.stopCh = stop
	c.stopMu.Unlock()
}

func (c *Cache) currentStopCh() <-chan struct{} {
	c.stopMu.RLock()
	defer c.stopMu.RUnlock()
	return c.stopCh
}

func (c *Cache) isStopped() bool {
	return stopClosed(c.currentStopCh())
}

func stopClosed(stop <-chan struct{}) bool {
	if stop == nil {
		return false
	}
	select {
	case <-stop:
		return true
	default:
		return false
	}
}

func (c *Cache) clearFetching(key string) {
	c.mu.Lock()
	delete(c.fetching, key)
	c.mu.Unlock()
}

// scheduleRetry runs fn after delay unless the cache's stop channel
// closes first. Always returns immediately. Cancellation is necessary
// because the longest checksum-retry backoff (1 hour) survives daemon
// shutdown otherwise, causing wp.org fetches against torn-down state.
func (c *Cache) scheduleRetry(delay time.Duration, fn func(), onCancel func()) {
	stop := c.currentStopCh()
	go func() {
		if stopClosed(stop) {
			runCancel(onCancel)
			return
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			if stopClosed(stop) {
				runCancel(onCancel)
				return
			}
			fn()
		case <-stop:
			runCancel(onCancel)
		}
	}()
}

func runCancel(onCancel func()) {
	if onCancel != nil {
		onCancel()
	}
}
