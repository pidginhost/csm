package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

// CMSHashCache stores SHA256 hashes of verified-clean CMS core files.
// After wp core verify-checksums confirms an installation is clean,
// all its core files are hashed and cached. The real-time scanner
// checks this cache before reporting signature matches — if a file's
// hash is in the cache, it's a known-clean CMS file and signature
// matches on it are false positives.
type CMSHashCache struct {
	mu     sync.RWMutex
	hashes map[string]bool // SHA256 hex → true
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
		}
	})
	return globalCache
}

// Add inserts a file hash into the cache.
func (c *CMSHashCache) Add(hash string) {
	c.mu.Lock()
	c.hashes[hash] = true
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

// Clear removes all cached hashes (used before rebuilding).
func (c *CMSHashCache) Clear() {
	c.mu.Lock()
	c.hashes = make(map[string]bool)
	c.mu.Unlock()
}

// HashFile computes the SHA256 hash of a file. Returns empty string on error.
func HashFile(path string) string {
	f, err := os.Open(path)
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
