package checks

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

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
