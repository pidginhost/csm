package processctx

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"
)

// Cache is a bounded LRU cache of processEntry keyed by PID with a per-entry
// TTL. Reads and writes are safe for concurrent use. now is a seam for
// deterministic testing.
type Cache struct {
	mu        sync.Mutex
	cap       int
	ttl       time.Duration
	ll        *list.List            // front = most-recently-used
	index     map[int]*list.Element // pid -> element holding *processEntry
	now       func() time.Time
	evictions atomic.Uint64
	ttlPurges atomic.Uint64
	misses    atomic.Uint64
}

// Stats is a snapshot of cache counters. Safe to call concurrently.
type Stats struct {
	Entries   int
	Evictions uint64 // LRU evictions (cap exceeded)
	TTLPurges uint64 // entries dropped because ttl expired on Get
	Misses    uint64 // Get returned no entry (includes ttl purges)
}

// NewCache returns a cache with the given hard cap and TTL.
func NewCache(cap int, ttl time.Duration) *Cache {
	if cap <= 0 {
		cap = 1
	}
	return &Cache{
		cap:   cap,
		ttl:   ttl,
		ll:    list.New(),
		index: make(map[int]*list.Element, cap),
		now:   time.Now,
	}
}

// Put inserts or updates an entry. lastTouch is set to now.
func (c *Cache) Put(e processEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.lastTouch = c.now()
	if el, ok := c.index[e.PID]; ok {
		el.Value = &e
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&e)
	c.index[e.PID] = el
	for c.ll.Len() > c.cap {
		c.evictOldestLocked()
	}
}

// Get returns the entry for pid if present and not TTL-expired. Touching
// an entry promotes it in LRU order.
func (c *Cache) Get(pid int) (processEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.index[pid]
	if !ok {
		c.misses.Add(1)
		return processEntry{}, false
	}
	entry := el.Value.(*processEntry)
	if c.ttl > 0 && c.now().Sub(entry.lastTouch) > c.ttl {
		c.removeLocked(el)
		c.ttlPurges.Add(1)
		c.misses.Add(1)
		return processEntry{}, false
	}
	entry.lastTouch = c.now()
	c.ll.MoveToFront(el)
	return *entry, true
}

// Len returns the number of live entries (without forcing TTL purge).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// Stats returns a counter snapshot.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	n := c.ll.Len()
	c.mu.Unlock()
	return Stats{
		Entries:   n,
		Evictions: c.evictions.Load(),
		TTLPurges: c.ttlPurges.Load(),
		Misses:    c.misses.Load(),
	}
}

func (c *Cache) evictOldestLocked() {
	el := c.ll.Back()
	if el == nil {
		return
	}
	c.removeLocked(el)
	c.evictions.Add(1)
}

func (c *Cache) removeLocked(el *list.Element) {
	entry := el.Value.(*processEntry)
	delete(c.index, entry.PID)
	c.ll.Remove(el)
}

// PutFromExec is a minimal constructor for callers that have only
// PID/UID/comm/exe from an exec event. UIDKnown is true even for UID 0.
func (c *Cache) PutFromExec(pid, ppid, uid int, comm, exe string) {
	c.Put(processEntry{PID: pid, PPID: ppid, UID: uid, UIDKnown: true, Comm: comm, Exe: exe})
}

// PutFromProc inserts a fully populated entry from /proc-style data. The
// current enricher validates and writes inside processctx; this helper keeps a
// public constructor for tests and future non-daemon callers without exposing
// processEntry.
func (c *Cache) PutFromProc(pid, ppid, uid int, user, account, comm, exe string, cmdline []string) {
	c.Put(processEntry{
		PID: pid, PPID: ppid, UID: uid, UIDKnown: true,
		User: user, Account: account,
		Comm: comm, Exe: exe, Cmdline: cmdline, ProcRead: true,
	})
}
