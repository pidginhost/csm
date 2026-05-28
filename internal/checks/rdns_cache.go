package checks

import (
	"container/list"
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
// evicted on insert once the cap is reached.
type RDNSCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	deadln  time.Duration
	maxSize int
	resolve func(ip net.IP) (string, error)
	now     func() time.Time
	order   *list.List
	entries map[string]*list.Element
}

type rdnsEntry struct {
	key      string
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
		order:   list.New(),
		entries: map[string]*list.Element{},
	}
}

// evictOldestLocked drops the oldest cached entry. Caller holds c.mu.
func (c *RDNSCache) evictOldestLocked() {
	el := c.order.Front()
	if el == nil {
		return
	}
	entry := el.Value.(*rdnsEntry)
	delete(c.entries, entry.key)
	c.order.Remove(el)
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
	now := c.now()
	if el, ok := c.entries[key]; ok {
		e := el.Value.(*rdnsEntry)
		if now.Sub(e.cachedAt) <= c.ttl {
			c.mu.Unlock()
			return e.host
		}
	}
	c.mu.Unlock()

	host := c.runWithDeadline(ip)

	c.mu.Lock()
	now = c.now()
	if el, present := c.entries[key]; present {
		e := el.Value.(*rdnsEntry)
		e.host = host
		e.cachedAt = now
		c.order.MoveToBack(el)
		c.mu.Unlock()
		return host
	}
	if c.order.Len() >= c.maxSize {
		c.evictOldestLocked()
	}
	c.entries[key] = c.order.PushBack(&rdnsEntry{key: key, host: host, cachedAt: now})
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
