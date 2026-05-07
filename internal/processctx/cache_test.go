package processctx

import (
	"testing"
	"time"
)

func newTestCache(cap int, ttl time.Duration) *Cache {
	c := NewCache(cap, ttl)
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return c
}

func TestCacheInsertAndLookup(t *testing.T) {
	c := newTestCache(8, time.Minute)
	c.Put(processEntry{PID: 100, UID: 1001, Comm: "php-fpm"})
	got, ok := c.Get(100)
	if !ok {
		t.Fatal("expected entry, got miss")
	}
	if got.UID != 1001 || got.Comm != "php-fpm" {
		t.Errorf("unexpected entry: %+v", got)
	}
}

func TestCacheMissReturnsFalse(t *testing.T) {
	c := newTestCache(8, time.Minute)
	if _, ok := c.Get(999); ok {
		t.Fatal("expected miss")
	}
}

func TestCacheTTLEviction(t *testing.T) {
	c := newTestCache(8, time.Minute)
	c.Put(processEntry{PID: 100, UID: 1001})
	c.now = func() time.Time { return time.Unix(1_700_000_000+61, 0) }
	if _, ok := c.Get(100); ok {
		t.Fatal("expected TTL eviction")
	}
	if c.Len() != 0 {
		t.Errorf("expected len 0 after TTL purge, got %d", c.Len())
	}
}

func TestCacheLRUEvictionAtCap(t *testing.T) {
	c := newTestCache(3, time.Hour)
	c.Put(processEntry{PID: 1})
	c.Put(processEntry{PID: 2})
	c.Put(processEntry{PID: 3})
	// Touch PID 1 so it is most-recently-used.
	if _, ok := c.Get(1); !ok {
		t.Fatal("setup: PID 1 missing")
	}
	// Insert PID 4 -> should evict PID 2 (oldest by access).
	c.Put(processEntry{PID: 4})
	if c.Len() != 3 {
		t.Errorf("expected len 3, got %d", c.Len())
	}
	if _, ok := c.Get(2); ok {
		t.Fatal("expected PID 2 evicted")
	}
	for _, pid := range []int{1, 3, 4} {
		if _, ok := c.Get(pid); !ok {
			t.Errorf("expected PID %d present", pid)
		}
	}
}

func TestCacheUpdateOverwrites(t *testing.T) {
	c := newTestCache(8, time.Minute)
	c.Put(processEntry{PID: 100, Comm: "old"})
	c.Put(processEntry{PID: 100, Comm: "new"})
	got, _ := c.Get(100)
	if got.Comm != "new" {
		t.Errorf("expected new, got %q", got.Comm)
	}
	if c.Len() != 1 {
		t.Errorf("expected len 1 after overwrite, got %d", c.Len())
	}
}

func TestCacheStats(t *testing.T) {
	c := newTestCache(2, time.Hour)
	c.Put(processEntry{PID: 1})
	c.Put(processEntry{PID: 2})
	c.Put(processEntry{PID: 3}) // evicts PID 1
	c.Get(2)
	c.Get(99) // miss
	s := c.Stats()
	if s.Entries != 2 {
		t.Errorf("Entries: want 2, got %d", s.Entries)
	}
	if s.Evictions != 1 {
		t.Errorf("Evictions: want 1, got %d", s.Evictions)
	}
	if s.Misses != 1 {
		t.Errorf("Misses: want 1, got %d", s.Misses)
	}
	if s.TTLPurges != 0 {
		t.Errorf("TTLPurges: want 0 (no TTL trips), got %d", s.TTLPurges)
	}
}

func TestCacheTTLPurgeCounter(t *testing.T) {
	c := newTestCache(8, time.Minute)
	c.Put(processEntry{PID: 100})
	c.now = func() time.Time { return time.Unix(1_700_000_000+61, 0) }
	if _, ok := c.Get(100); ok {
		t.Fatal("expected TTL eviction")
	}
	s := c.Stats()
	if s.TTLPurges != 1 {
		t.Errorf("TTLPurges: want 1, got %d", s.TTLPurges)
	}
	if s.Misses != 1 {
		t.Errorf("Misses: want 1 (TTL counts as miss too), got %d", s.Misses)
	}
	if s.Evictions != 0 {
		t.Errorf("Evictions: want 0 (LRU not triggered), got %d", s.Evictions)
	}
}
