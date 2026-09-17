package wpcheck

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type Cache struct {
	mu              sync.RWMutex
	statePath       string
	checksums       map[string]map[string]string // core: "<version>:<locale>" -> relPath -> MD5
	pluginChecksums map[string]map[string]string // plugins: "<slug>:<version>" -> relPath -> SHA256
	roots           map[string]rootEntry
	fetching        map[string]bool
	// Retain admission times after completion so fast responses and repeated
	// misses cannot turn tenant-written release names into unlimited fetches.
	coreFetchAfter map[string]time.Time

	// pluginNotFoundUntil records slug+version pairs that wordpress.org
	// returned 404 for, paired with the absolute time at which the
	// suppression expires. Plugins hosted outside wp.org (paid forks,
	// custom internal plugins) would otherwise re-arm the 4-attempt
	// retry cycle on every cache miss. The TTL ensures wp.org adding
	// a plugin later still gets picked up.
	pluginNotFoundUntil map[string]time.Time

	// stopCh, when non-nil and closed, signals pending retry timers to
	// drop their scheduled fetch instead of firing. Wired by the daemon
	// to the FileMonitor stopCh so checksum-retry chains do not survive
	// daemon shutdown.
	stopMu sync.RWMutex
	stopCh <-chan struct{}
}

type rootEntry struct {
	version string
	locale  string
}

func NewCache(statePath string) *Cache {
	c := &Cache{
		statePath:           statePath,
		checksums:           make(map[string]map[string]string),
		pluginChecksums:     make(map[string]map[string]string),
		roots:               make(map[string]rootEntry),
		fetching:            make(map[string]bool),
		coreFetchAfter:      make(map[string]time.Time),
		pluginNotFoundUntil: make(map[string]time.Time),
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
		// #nosec G304 -- dir is {statePath}/wp-checksums; name comes from
		// our own os.ReadDir of that same dir.
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

const (
	coreFetchMaxPending = 8
	coreFetchHistoryMax = 64
	coreFetchCooldown   = time.Hour
)

func (c *Cache) startBackgroundFetch(version, locale string) {
	if c.isStopped() {
		return
	}
	key := cacheKey(version, locale)
	c.mu.Lock()
	if c.fetching[key] || c.checksums[key] != nil || len(c.fetching) >= coreFetchMaxPending {
		c.mu.Unlock()
		return
	}
	now := time.Now()
	for oldKey, until := range c.coreFetchAfter {
		if !now.Before(until) && !c.fetching[oldKey] {
			delete(c.coreFetchAfter, oldKey)
		}
	}
	if now.Before(c.coreFetchAfter[key]) || len(c.coreFetchAfter) >= coreFetchHistoryMax {
		c.mu.Unlock()
		return
	}
	c.coreFetchAfter[key] = now.Add(coreFetchCooldown)
	c.fetching[key] = true
	c.mu.Unlock()
	go c.fetchWithRetry(version, locale, 0)
}

func (c *Cache) fetchWithRetry(version, locale string, attempt int) {
	backoffs := []time.Duration{1 * time.Minute, 5 * time.Minute, 15 * time.Minute, 1 * time.Hour}
	key := cacheKey(version, locale)

	if c.isStopped() {
		c.clearFetching(key)
		return
	}

	rawJSON, checksums, err := FetchChecksums(version, locale)
	if err != nil {
		if attempt >= len(backoffs) {
			c.mu.Lock()
			c.coreFetchAfter[key] = time.Now().Add(coreFetchCooldown)
			delete(c.fetching, key)
			c.mu.Unlock()
			fmt.Fprintf(os.Stderr, "wpcheck: core fetch abandoned for WP %s (%s) after %d attempts: %v\n",
				version, locale, attempt+1, err)
			return
		}
		delay := backoffs[attempt]
		fmt.Fprintf(os.Stderr, "wpcheck: fetch failed for WP %s (%s), retry in %v: %v\n",
			version, locale, delay, err)
		c.scheduleRetry(delay, func() {
			c.fetchWithRetry(version, locale, attempt+1)
		}, func() {
			c.clearFetching(key)
		})
		return
	}

	if err := c.PersistChecksums(version, locale, rawJSON, checksums); err != nil {
		fmt.Fprintf(os.Stderr, "wpcheck: persist failed for WP %s (%s): %v\n", version, locale, err)
	}

	c.clearFetching(key)

	fmt.Fprintf(os.Stderr, "wpcheck: cached %d checksums for WP %s (%s)\n", len(checksums), version, locale)
}

const maxFileSize = 2 << 20

// readCompleteFileForHash returns a stable-size snapshot of a regular file.
// Hash verification must never accept only a prefix: if a known-good file is
// exactly maxFileSize bytes, an attacker could otherwise append a payload that
// the one-shot bounded Pread silently ignores.
func readCompleteFileForHash(fd int) []byte {
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Size <= 0 || before.Size > maxFileSize {
		return nil
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil
	}

	data := make([]byte, int(before.Size))
	offset := 0
	interrupts := 0
	for offset < len(data) {
		n, err := unix.Pread(fd, data[offset:], int64(offset))
		if n > 0 {
			offset += n
			interrupts = 0
		}
		if err != nil && !errors.Is(err, unix.EINTR) {
			return nil
		}
		if n == 0 {
			if !errors.Is(err, unix.EINTR) {
				return nil
			}
			interrupts++
			if interrupts > 100 {
				return nil
			}
		}
	}

	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || before.Dev != after.Dev ||
		before.Ino != after.Ino || before.Size != after.Size {
		return nil
	}
	return data
}
