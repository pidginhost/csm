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

// scheduleRetry runs fn after delay unless the cache's stop channel
// closes first. Always returns immediately. Cancellation is necessary
// because the longest checksum-retry backoff (1 hour) survives daemon
// shutdown otherwise, causing wp.org fetches against torn-down state.
func (c *Cache) scheduleRetry(delay time.Duration, fn func()) {
	stop := c.currentStopCh()
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			fn()
		case <-stop:
		}
	}()
}
