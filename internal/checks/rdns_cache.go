package checks

import (
	"net"
	"sync"
	"time"
)

// RDNSCacheConfig is the config block for NewRDNSCache. Resolve is the
// function used to perform the actual reverse lookup; production
// callers wrap net.LookupAddr. ResolveDeadline bounds each lookup;
// 0 disables the deadline.
type RDNSCacheConfig struct {
	TTL             time.Duration
	Resolve         func(ip net.IP) (string, error)
	ResolveDeadline time.Duration
}

// RDNSCache is a small TTL cache around reverse DNS lookups. Cached
// negative results (resolver error / NXDOMAIN) are kept until TTL too,
// so the detector does not hammer a slow resolver on a known-bad IP.
type RDNSCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	deadln  time.Duration
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
	return &RDNSCache{
		ttl:     cfg.TTL,
		deadln:  cfg.ResolveDeadline,
		resolve: cfg.Resolve,
		now:     time.Now,
		entries: map[string]rdnsEntry{},
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
