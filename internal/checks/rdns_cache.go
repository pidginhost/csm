package checks

import (
	"net"
	"sync"
	"time"
)

// RDNSCacheConfig is the config block for NewRDNSCache. Resolve is the
// function used to perform the actual reverse lookup; production
// callers wrap net.LookupAddr. ResolveDeadline bounds each lookup;
// 0 disables the deadline. MaxSize caps the number of cached entries
// to keep memory bounded on hosts that see a wide spread of remote
// IPs (BPF SMTP-egress is the motivating case); the oldest entry by
// cachedAt is evicted before a new one is inserted past the cap.
// 0 falls back to rdnsCacheDefaultMaxSize.
type RDNSCacheConfig struct {
	TTL             time.Duration
	Resolve         func(ip net.IP) (string, error)
	ResolveDeadline time.Duration
	MaxSize         int
}

const rdnsCacheDefaultMaxSize = 10000

// RDNSCache is a small TTL cache around reverse DNS lookups. Cached
// negative results (resolver error / NXDOMAIN) are kept until TTL too,
// so the detector does not hammer a slow resolver on a known-bad IP.
// Entries are capped at maxSize; the oldest-by-cachedAt entry is
// evicted on insert once the cap is reached. Sweep() drops anything
// older than 2*TTL and is intended for a daemon-driven retention loop.
type RDNSCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	deadln  time.Duration
	maxSize int
	resolve func(ip net.IP) (string, error)
	now     func() time.Time
	entries map[string]rdnsEntry
}

type rdnsEntry struct {
	host     string
	cachedAt time.Time
}

// NewRDNSCache returns a ready cache.
func NewRDNSCache(cfg RDNSCacheConfig) *RDNSCache {
	maxSize := cfg.MaxSize
	if maxSize <= 0 {
		maxSize = rdnsCacheDefaultMaxSize
	}
	return &RDNSCache{
		ttl:     cfg.TTL,
		deadln:  cfg.ResolveDeadline,
		maxSize: maxSize,
		resolve: cfg.Resolve,
		now:     time.Now,
		entries: map[string]rdnsEntry{},
	}
}

// Len returns the current cached entry count. Used by tests.
func (c *RDNSCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// contains reports whether the cache currently holds an entry for the
// stringified ip. Used by tests.
func (c *RDNSCache) contains(ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[ip]
	return ok
}

// Sweep drops entries whose cachedAt is older than 2x TTL. Safe to
// call from a periodic retention loop; bounded by maxSize.
func (c *RDNSCache) Sweep() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := c.now().Add(-2 * c.ttl)
	removed := 0
	for key, entry := range c.entries {
		if entry.cachedAt.Before(cutoff) {
			delete(c.entries, key)
			removed++
		}
	}
	return removed
}

// evictOldestLocked drops the single entry with the smallest cachedAt.
// Caller holds c.mu. O(N); only runs at insert time when len == maxSize.
func (c *RDNSCache) evictOldestLocked() {
	var oldestKey string
	var oldestAt time.Time
	first := true
	for key, entry := range c.entries {
		if first || entry.cachedAt.Before(oldestAt) {
			oldestKey = key
			oldestAt = entry.cachedAt
			first = false
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// Lookup returns the cached hostname for ip, or "" on miss/error/deadline.
// Lookup blocks the caller for at most cfg.ResolveDeadline; cache hits
// return immediately.
func (c *RDNSCache) Lookup(ip net.IP) string {
	if ip == nil {
		return ""
	}
	key := ip.String()
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && c.now().Sub(e.cachedAt) <= c.ttl {
		c.mu.Unlock()
		return e.host
	}
	c.mu.Unlock()

	host := c.runWithDeadline(ip)

	c.mu.Lock()
	if _, present := c.entries[key]; !present && len(c.entries) >= c.maxSize {
		c.evictOldestLocked()
	}
	c.entries[key] = rdnsEntry{host: host, cachedAt: c.now()}
	c.mu.Unlock()
	return host
}

func (c *RDNSCache) runWithDeadline(ip net.IP) string {
	if c.deadln <= 0 {
		host, err := c.resolve(ip)
		if err != nil {
			return ""
		}
		return host
	}
	type result struct {
		host string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		host, err := c.resolve(ip)
		ch <- result{host, err}
	}()
	timer := time.NewTimer(c.deadln)
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.err != nil {
			return ""
		}
		return r.host
	case <-timer.C:
		return ""
	}
}
