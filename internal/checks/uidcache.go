package checks

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// uidCache caches uid -> username from /etc/passwd. The first Lookup of an
// unknown uid reads and parses the file; subsequent lookups return from the
// in-memory map. Process-lifetime: callers that need fresh data after a
// useradd should call Refresh().
type uidCache struct {
	path  string
	mu    sync.RWMutex
	m     map[uint32]string
	homes map[string]string
}

var defaultUIDCache = newUIDCache("/etc/passwd")

func newUIDCache(path string) *uidCache {
	return &uidCache{path: path, m: map[uint32]string{}, homes: map[string]string{}}
}

// LookupUser returns the username for uid, or "uid:<n>" if not resolvable.
// Safe for concurrent use; the underlying cache is shared across the daemon.
func LookupUser(uid uint32) string { return defaultUIDCache.Lookup(uid) }

// swapDefaultUIDCacheForTest replaces defaultUIDCache with a cache pointed at
// path and returns a function that restores the original. Test-only helper:
// existing tests stub /etc/passwd via osFS, but the cache reads the real file
// directly (so the daemon never burns syscalls per-event). This shim lets the
// tests stage a fixture file and have LookupUser read from it.
func swapDefaultUIDCacheForTest(path string) func() {
	prev := defaultUIDCache
	defaultUIDCache = newUIDCache(path)
	return func() { defaultUIDCache = prev }
}

// SwapUIDCacheForTest is the exported form of swapDefaultUIDCacheForTest for
// packages whose producers resolve uids through LookupUser.
func SwapUIDCacheForTest(path string) func() { return swapDefaultUIDCacheForTest(path) }

func (c *uidCache) Lookup(uid uint32) string {
	c.mu.RLock()
	if name, ok := c.m[uid]; ok {
		c.mu.RUnlock()
		return name
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if name, ok := c.m[uid]; ok {
		return name
	}
	c.parseLocked()
	if name, ok := c.m[uid]; ok {
		return name
	}
	miss := fmt.Sprintf("uid:%d", uid)
	c.m[uid] = miss
	return miss
}

// Refresh drops the cache. The next Lookup re-reads /etc/passwd.
func (c *uidCache) Refresh() {
	c.mu.Lock()
	c.m = map[uint32]string{}
	c.homes = map[string]string{}
	c.mu.Unlock()
}

// HomeDir returns the home directory recorded for name, or "" when the user
// is unknown. Producers use it to tell a hosting account from a system user.
func (c *uidCache) HomeDir(name string) string {
	c.mu.RLock()
	home, ok := c.homes[name]
	c.mu.RUnlock()
	if ok {
		return home
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if home, ok := c.homes[name]; ok {
		return home
	}
	c.parseLocked()
	return c.homes[name]
}

// parseLocked replaces the cache contents with a fresh scan. Caller holds the
// write lock.
func (c *uidCache) parseLocked() {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(line, ":", 7)
		if len(fields) < 3 {
			continue
		}
		uid64, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		c.m[uint32(uid64)] = fields[0]
		if len(fields) >= 6 {
			c.homes[fields[0]] = fields[5]
		}
	}
}
