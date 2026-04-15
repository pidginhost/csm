package wpcheck

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type Cache struct {
	mu        sync.RWMutex
	statePath string
	checksums map[string]map[string]string
	roots     map[string]rootEntry
	fetching  map[string]bool
}

type rootEntry struct {
	version string
	locale  string
}

func NewCache(statePath string) *Cache {
	c := &Cache{
		statePath: statePath,
		checksums: make(map[string]map[string]string),
		roots:     make(map[string]rootEntry),
		fetching:  make(map[string]bool),
	}
	c.loadFromDisk()
	return c
}

func cacheKey(version, locale string) string {
	return version + ":" + locale
}

func diskFilename(version, locale string) string {
	return version + "_" + locale + ".json"
}

func (c *Cache) loadFromDisk() {
	dir := filepath.Join(c.statePath, "wp-checksums")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		checksums, err := ParseChecksumResponse(data)
		if err != nil {
			continue
		}
		base := strings.TrimSuffix(name, ".json")
		parts := strings.SplitN(base, "_", 2)
		if len(parts) != 2 {
			continue
		}
		c.checksums[cacheKey(parts[0], parts[1])] = checksums
	}
}

// PersistChecksums writes checksum data to disk atomically (tmpfile + rename)
// and populates the in-memory cache. The file is written to {statePath}/wp-checksums/.
func (c *Cache) PersistChecksums(version, locale string, rawJSON []byte, checksums map[string]string) error {
	dir := filepath.Join(c.statePath, "wp-checksums")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating wp-checksums dir: %w", err)
	}
	filename := diskFilename(version, locale)
	tmpPath := filepath.Join(dir, filename+".tmp")
	finalPath := filepath.Join(dir, filename)
	if err := os.WriteFile(tmpPath, rawJSON, 0600); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming to final: %w", err)
	}
	c.mu.Lock()
	c.checksums[cacheKey(version, locale)] = checksums
	c.mu.Unlock()
	return nil
}

func (c *Cache) lookupChecksum(version, locale, relativePath string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	versionMap, ok := c.checksums[cacheKey(version, locale)]
	if !ok {
		return "", false
	}
	md5hex, ok := versionMap[relativePath]
	return md5hex, ok
}

func (c *Cache) hasChecksums(version, locale string) bool {
	c.mu.RLock()
	ok := c.checksums[cacheKey(version, locale)] != nil
	c.mu.RUnlock()
	return ok
}

func (c *Cache) getRoot(root string) (version, locale string, ok bool) {
	c.mu.RLock()
	entry, ok := c.roots[root]
	c.mu.RUnlock()
	if !ok {
		return "", "", false
	}
	return entry.version, entry.locale, true
}

func (c *Cache) setRoot(root, version, locale string) {
	c.mu.Lock()
	c.roots[root] = rootEntry{version: version, locale: locale}
	c.mu.Unlock()
}

func (c *Cache) invalidateRoot(root string) {
	c.mu.Lock()
	delete(c.roots, root)
	c.mu.Unlock()
}

func (c *Cache) startBackgroundFetch(version, locale string) {
	key := cacheKey(version, locale)
	c.mu.Lock()
	if c.fetching[key] {
		c.mu.Unlock()
		return
	}
	c.fetching[key] = true
	c.mu.Unlock()
	go c.fetchWithRetry(version, locale, 0)
}

func (c *Cache) fetchWithRetry(version, locale string, attempt int) {
	backoffs := []time.Duration{1 * time.Minute, 5 * time.Minute, 15 * time.Minute, 1 * time.Hour}

	rawJSON, checksums, err := FetchChecksums(version, locale)
	if err != nil {
		delay := backoffs[len(backoffs)-1]
		if attempt < len(backoffs) {
			delay = backoffs[attempt]
		}
		fmt.Fprintf(os.Stderr, "wpcheck: fetch failed for WP %s (%s), retry in %v: %v\n",
			version, locale, delay, err)
		time.AfterFunc(delay, func() {
			c.fetchWithRetry(version, locale, attempt+1)
		})
		return
	}

	if err := c.PersistChecksums(version, locale, rawJSON, checksums); err != nil {
		fmt.Fprintf(os.Stderr, "wpcheck: persist failed for WP %s (%s): %v\n", version, locale, err)
	}

	c.mu.Lock()
	delete(c.fetching, cacheKey(version, locale))
	c.mu.Unlock()

	fmt.Fprintf(os.Stderr, "wpcheck: cached %d checksums for WP %s (%s)\n", len(checksums), version, locale)
}

const maxFileSize = 2 << 20

func (c *Cache) IsVerifiedCoreFile(fd int, path string) bool {
	root := DetectWPRoot(path)
	if root == "" {
		return false
	}

	relPath := RelativePath(root, path)
	if relPath == "" {
		return false
	}

	if relPath == filepath.Join("wp-includes", "version.php") {
		c.invalidateRoot(root)
	}

	version, locale, ok := c.getRoot(root)
	if !ok {
		var err error
		version, locale, err = ReadVersionFile(root)
		if err != nil {
			return false
		}
		c.setRoot(root, version, locale)
	}

	if !c.hasChecksums(version, locale) {
		c.startBackgroundFetch(version, locale)
		return false
	}

	expectedMD5, ok := c.lookupChecksum(version, locale, relPath)
	if !ok {
		return false
	}

	data := make([]byte, maxFileSize)
	n, err := unix.Pread(fd, data, 0)
	if n <= 0 || (err != nil && n == 0) {
		return false
	}
	data = data[:n]

	hash := md5.Sum(data)
	actualMD5 := hex.EncodeToString(hash[:])

	if actualMD5 == expectedMD5 {
		return true
	}

	c.invalidateRoot(root)
	newVersion, newLocale, err := ReadVersionFile(root)
	if err != nil || (newVersion == version && newLocale == locale) {
		return false
	}

	c.setRoot(root, newVersion, newLocale)
	if !c.hasChecksums(newVersion, newLocale) {
		c.startBackgroundFetch(newVersion, newLocale)
		return false
	}

	newExpectedMD5, ok := c.lookupChecksum(newVersion, newLocale, relPath)
	if !ok {
		return false
	}
	return actualMD5 == newExpectedMD5
}
