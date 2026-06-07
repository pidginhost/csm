package checks

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func rdnsCacheLen(c *RDNSCache) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

func rdnsCacheContains(c *RDNSCache, ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[ip]
	return ok
}

func TestRDNSCacheReturnsCachedHit(t *testing.T) {
	var calls atomic.Int64
	c := NewRDNSCache(RDNSCacheConfig{
		TTL: time.Minute,
		Resolve: func(ip net.IP) (string, error) {
			calls.Add(1)
			return "host.example.com", nil
		},
	})
	got1 := c.Lookup(net.ParseIP("203.0.113.10").To4())
	got2 := c.Lookup(net.ParseIP("203.0.113.10").To4())
	if got1 != "host.example.com" || got2 != "host.example.com" {
		t.Errorf("got1=%q got2=%q", got1, got2)
	}
	if calls.Load() != 1 {
		t.Errorf("Resolve calls: want 1 (cached), got %d", calls.Load())
	}
}

func TestRDNSCacheTTLExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var calls atomic.Int64
	c := NewRDNSCache(RDNSCacheConfig{
		TTL: time.Minute,
		Resolve: func(ip net.IP) (string, error) {
			calls.Add(1)
			return "host.example.com", nil
		},
	})
	c.now = func() time.Time { return now }
	c.Lookup(net.ParseIP("203.0.113.10").To4())
	now = now.Add(2 * time.Minute)
	c.Lookup(net.ParseIP("203.0.113.10").To4())
	if calls.Load() != 2 {
		t.Errorf("Resolve calls after TTL: want 2, got %d", calls.Load())
	}
}

func TestRDNSCacheResolveErrorReturnsEmptyAndIsCached(t *testing.T) {
	var calls atomic.Int64
	c := NewRDNSCache(RDNSCacheConfig{
		TTL: time.Minute,
		Resolve: func(ip net.IP) (string, error) {
			calls.Add(1)
			return "", errors.New("nxdomain")
		},
	})
	got1 := c.Lookup(net.ParseIP("203.0.113.20").To4())
	got2 := c.Lookup(net.ParseIP("203.0.113.20").To4())
	if got1 != "" || got2 != "" {
		t.Errorf("expected empty on error; got %q, %q", got1, got2)
	}
	if calls.Load() != 1 {
		t.Errorf("Resolve calls: want 1 (negative cache); got %d", calls.Load())
	}
}

func TestRDNSCacheEvictsOldestWhenCapExceeded(t *testing.T) {
	c := NewRDNSCache(RDNSCacheConfig{
		TTL:     time.Hour,
		MaxSize: 3,
		Resolve: func(ip net.IP) (string, error) {
			return "host-" + ip.String(), nil
		},
	})
	c.Lookup(net.ParseIP("203.0.113.1").To4())
	c.Lookup(net.ParseIP("203.0.113.2").To4())
	c.Lookup(net.ParseIP("203.0.113.3").To4())
	c.Lookup(net.ParseIP("203.0.113.4").To4()) // forces eviction

	if got := rdnsCacheLen(c); got != 3 {
		t.Errorf("cache size = %d, want 3 after eviction", got)
	}
	if rdnsCacheContains(c, "203.0.113.1") {
		t.Errorf("oldest entry 203.0.113.1 should have been evicted")
	}
	for _, ip := range []string{"203.0.113.2", "203.0.113.3", "203.0.113.4"} {
		if !rdnsCacheContains(c, ip) {
			t.Errorf("%s should still be cached", ip)
		}
	}
}

func TestRDNSCacheEvictsFirstInsertedWhenTimestampsTie(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for range 64 {
		c := NewRDNSCache(RDNSCacheConfig{
			TTL:     time.Hour,
			MaxSize: 2,
			Resolve: func(ip net.IP) (string, error) {
				return "host-" + ip.String(), nil
			},
		})
		c.now = func() time.Time { return now }

		c.Lookup(net.ParseIP("203.0.113.10").To4())
		c.Lookup(net.ParseIP("203.0.113.20").To4())
		c.Lookup(net.ParseIP("203.0.113.30").To4())

		if rdnsCacheContains(c, "203.0.113.10") {
			t.Fatalf("oldest tied entry should have been evicted")
		}
		if !rdnsCacheContains(c, "203.0.113.20") || !rdnsCacheContains(c, "203.0.113.30") {
			t.Fatalf("newer tied entries should remain cached")
		}
	}
}

// TestRDNSCacheBoundsConcurrentResolves proves the deadline path caps the
// number of in-flight resolve goroutines. A resolve goroutine blocked on a
// wedged DNS server cannot be cancelled in Go, so without a cap a burst of
// distinct IPs under deadline saturation spawns one abandonable goroutine per
// IP. With MaxConcurrent the cache spawns at most that many; the rest fail
// fast and return "" exactly as a deadline miss would.
func TestRDNSCacheBoundsConcurrentResolves(t *testing.T) {
	const maxConcurrent = 2
	release := make(chan struct{})
	var inflight, peak atomic.Int32

	c := NewRDNSCache(RDNSCacheConfig{
		TTL:             time.Minute,
		ResolveDeadline: 25 * time.Millisecond,
		MaxConcurrent:   maxConcurrent,
		Resolve: func(ip net.IP) (string, error) {
			n := inflight.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			<-release
			inflight.Add(-1)
			return "host.example.com", nil
		},
	})

	var wg sync.WaitGroup
	for i := range 10 {
		ip := net.IPv4(203, 0, 113, byte(i)).To4()
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Lookup(ip)
		}()
	}
	wg.Wait() // every Lookup returns once its deadline fires
	close(release)

	if got := peak.Load(); got == 0 {
		t.Fatalf("resolver never ran; test did not exercise the deadline path")
	}
	if got := peak.Load(); got > maxConcurrent {
		t.Fatalf("peak concurrent resolves = %d, want <= %d", got, maxConcurrent)
	}
}

func TestRDNSCacheDeadlineExpiredReturnsEmpty(t *testing.T) {
	c := NewRDNSCache(RDNSCacheConfig{
		TTL: time.Minute,
		Resolve: func(ip net.IP) (string, error) {
			time.Sleep(2 * time.Second)
			return "host.example.com", nil
		},
		ResolveDeadline: 25 * time.Millisecond,
	})
	start := time.Now()
	got := c.Lookup(net.ParseIP("203.0.113.30").To4())
	elapsed := time.Since(start)
	if got != "" {
		t.Errorf("deadline must yield empty; got %q", got)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("deadline not honored; elapsed=%v", elapsed)
	}
}
