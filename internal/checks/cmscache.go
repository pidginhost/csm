package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync"
)

// CMSHashCache stores SHA256 hashes of verified-clean CMS core files.
// After wp core verify-checksums confirms an installation is clean,
// all its core files are hashed and cached. The real-time scanner
// checks this cache before reporting signature matches - if a file's
// hash is in the cache, it's a known-clean CMS file and signature
// matches on it are false positives.
type CMSHashCache struct {
	mu     sync.RWMutex
	hashes map[string]bool // SHA256 hex -> true
	sizes  map[int64]bool  // file sizes that can possibly match a cached hash
}

var (
	globalCache     *CMSHashCache
	globalCacheOnce sync.Once
)

// GlobalCMSCache returns the singleton cache, creating it on first call.
func GlobalCMSCache() *CMSHashCache {
	globalCacheOnce.Do(func() {
		globalCache = &CMSHashCache{
			hashes: make(map[string]bool),
			sizes:  make(map[int64]bool),
		}
	})
	return globalCache
}

// Add inserts a file hash and its content size into the cache.
func (c *CMSHashCache) Add(hash string, size int64) {
	c.mu.Lock()
	c.hashes[hash] = true
	c.sizes[size] = true
	c.mu.Unlock()
}

// Contains checks if a file hash is in the cache.
func (c *CMSHashCache) Contains(hash string) bool {
	c.mu.RLock()
	ok := c.hashes[hash]
	c.mu.RUnlock()
	return ok
}

// Size returns the number of cached hashes.
func (c *CMSHashCache) Size() int {
	c.mu.RLock()
	n := len(c.hashes)
	c.mu.RUnlock()
	return n
}

// MayContainSize reports whether a verified file of size bytes was cached.
// It lets realtime scanning reject attacker-sized files before hashing them.
func (c *CMSHashCache) MayContainSize(size int64) bool {
	c.mu.RLock()
	ok := c.sizes[size]
	c.mu.RUnlock()
	return ok
}

// Clear removes all cached hashes (used before rebuilding).
func (c *CMSHashCache) Clear() {
	c.mu.Lock()
	c.hashes = make(map[string]bool)
	c.sizes = make(map[int64]bool)
	c.mu.Unlock()
}

// HashFile computes the SHA256 hash of a file. Returns empty string on error.
func HashFile(path string) string {
	f, err := osFS.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// IsVerifiedCMSFile checks if a file at the given path matches a
// known-clean CMS core file by comparing its SHA256 hash against the cache.
//
// The cache is keyed by SHA256 hash alone (not path+hash) - this is correct:
//   - SHA256 preimage resistance makes it computationally infeasible for an
//     attacker to craft a file that produces the same hash as a legitimate
//     WP core file. Birthday attacks do not apply here because the attacker
//     must hit a specific pre-existing hash, not merely find any collision.
//   - If file content matches a known WP core file byte-for-byte, it IS that
//     file regardless of where it is located on disk. The path is irrelevant
//     to whether the content is clean.
func IsVerifiedCMSFile(path string) bool {
	cache := GlobalCMSCache()
	if cache.Size() == 0 {
		return false
	}
	hash := HashFile(path)
	if hash == "" {
		return false
	}
	return cache.Contains(hash)
}

// IsVerifiedCMSHash reports whether a content hash belongs to a verified CMS
// core file. Callers that already hold the content -- the realtime scanner
// hashes the event descriptor -- use this instead of IsVerifiedCMSFile, whose
// re-read resolves the path again and can hash something other than what was
// examined.
func IsVerifiedCMSHash(hash string) bool {
	if hash == "" {
		return false
	}
	cache := GlobalCMSCache()
	if cache.Size() == 0 {
		return false
	}
	return cache.Contains(hash)
}

// CMSCacheEmpty reports whether any verified core files are cached, so a caller
// can skip hashing entirely when the answer cannot be yes.
func CMSCacheEmpty() bool { return GlobalCMSCache().Size() == 0 }

// CMSCacheMayContainSize reports whether hashing a file of size bytes can
// possibly produce a cached CMS hash.
func CMSCacheMayContainSize(size int64) bool { return GlobalCMSCache().MayContainSize(size) }
