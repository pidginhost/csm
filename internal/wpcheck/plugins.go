package wpcheck

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Plugin verification mirrors the core-file verification path: when a file
// under /wp-content/plugins/<slug>/ matches the hash we computed from the
// plugin's official wordpress.org ZIP, signature/YARA rule matches on it are
// false positives and should not fire.

const pluginsSegment = "/wp-content/plugins/"

// DetectPluginRoot returns the plugin root directory and slug for a path that
// sits under /wp-content/plugins/<slug>/. Returns empty strings if the path
// is not inside a plugin.
func DetectPluginRoot(path string) (root, slug string) {
	idx := strings.Index(path, pluginsSegment)
	if idx < 0 {
		return "", ""
	}
	tail := path[idx+len(pluginsSegment):]
	slashIdx := strings.Index(tail, "/")
	if slashIdx <= 0 {
		return "", ""
	}
	slug = tail[:slashIdx]
	root = path[:idx+len(pluginsSegment)] + slug
	return root, slug
}

var rePluginVersionHeader = regexp.MustCompile(`(?im)^\s*\*?\s*Version:\s*([^\s]+)`)

// ReadPluginVersion extracts the Version: header from the plugin's main
// file (<pluginRoot>/<slug>.php). WordPress requires this header to exist
// on every published plugin.
func ReadPluginVersion(pluginRoot, slug string) (string, error) {
	mainPath := filepath.Join(pluginRoot, slug+".php")
	// #nosec G304 -- pluginRoot is derived from a path the scanner received
	// from fanotify under /wp-content/plugins/; slug is the immediate child
	// segment. The read is bounded by the header-detection limit below.
	f, err := os.Open(mainPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	if n <= 0 {
		return "", errors.New("empty plugin main file")
	}
	m := rePluginVersionHeader.FindSubmatch(buf[:n])
	if m == nil {
		return "", errors.New("version header not found in plugin main file")
	}
	return string(m[1]), nil
}

// pluginZipURL returns the canonical wordpress.org download URL for a given
// plugin slug and version.
func pluginZipURL(slug, version string) string {
	return fmt.Sprintf("https://downloads.wordpress.org/plugin/%s.%s.zip", slug, version)
}

// FetchPluginChecksums downloads the plugin ZIP from wordpress.org,
// extracts each file, and returns a map of relative path -> SHA256 hex.
// The returned paths are relative to the plugin root (the leading
// "<slug>/" prefix from the ZIP entries is stripped).
func FetchPluginChecksums(slug, version string) (map[string]string, error) {
	return fetchPluginChecksumsFromURL(pluginZipURL(slug, version), slug)
}

const maxPluginZipBytes = 100 << 20 // 100 MB ceiling

func fetchPluginChecksumsFromURL(url, slug string) (map[string]string, error) {
	resp, err := httpClient.Get(url) //nolint:gosec,bodyclose // httpClient has a timeout; body is closed below.
	if err != nil {
		return nil, fmt.Errorf("plugin zip GET failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("plugin zip HTTP %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPluginZipBytes))
	if err != nil {
		return nil, fmt.Errorf("reading plugin zip: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("opening plugin zip: %w", err)
	}
	out := make(map[string]string, len(zr.File))
	prefix := slug + "/"
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		name := zf.Name
		if !strings.HasPrefix(name, prefix) {
			// Malformed ZIP (e.g. nested into a differently-named folder).
			// Skip; callers detect partial results by checking cache emptiness.
			continue
		}
		rel := filepath.Clean(strings.TrimPrefix(name, prefix))
		// Reject path-traversal and absolute paths: a crafted ZIP entry
		// named "<slug>/../../etc/passwd" would otherwise land in the
		// checksum map. Defense-in-depth against a compromised CDN.
		if rel == "." || strings.HasPrefix(rel, "..") || strings.HasPrefix(rel, "/") {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, fmt.Errorf("opening zip entry %s: %w", name, err)
		}
		// Cap decompressed size per entry. Without this, a zip-bomb whose
		// compressed body fits under maxPluginZipBytes can still exhaust
		// memory during io.Copy. +1 lets us detect overflow.
		limited := io.LimitReader(rc, maxPluginZipBytes+1)
		h := sha256.New()
		nCopied, err := io.Copy(h, limited)
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("hashing zip entry %s: %w", name, err)
		}
		if nCopied > maxPluginZipBytes {
			return nil, fmt.Errorf("zip entry %s exceeds per-entry size cap", name)
		}
		out[rel] = hex.EncodeToString(h.Sum(nil))
	}
	if len(out) == 0 {
		return nil, errors.New("plugin zip yielded no checksums")
	}
	return out, nil
}

// --- Cache plugin support ------------------------------------------------

func pluginKey(slug, version string) string {
	return slug + ":" + version
}

func (c *Cache) setPluginChecksums(slug, version string, checksums map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pluginChecksums == nil {
		c.pluginChecksums = make(map[string]map[string]string)
	}
	c.pluginChecksums[pluginKey(slug, version)] = checksums
}

func (c *Cache) lookupPluginChecksum(slug, version, relPath string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, ok := c.pluginChecksums[pluginKey(slug, version)]
	if !ok {
		return "", false
	}
	h, ok := m[relPath]
	return h, ok
}

func (c *Cache) hasPluginChecksums(slug, version string) bool {
	c.mu.RLock()
	_, ok := c.pluginChecksums[pluginKey(slug, version)]
	c.mu.RUnlock()
	return ok
}

func (c *Cache) startBackgroundPluginFetch(slug, version string) {
	key := pluginKey(slug, version)
	c.mu.Lock()
	if c.fetching == nil {
		c.fetching = make(map[string]bool)
	}
	if c.fetching[key] {
		c.mu.Unlock()
		return
	}
	c.fetching[key] = true
	c.mu.Unlock()
	go c.fetchPluginWithRetry(slug, version, 0)
}

// fetchPluginWithRetry mirrors the core-checksum fetchWithRetry: the
// fetching flag stays set across retries so cache-miss events for the
// same slug/version do not spawn new goroutines. On exhaustion the flag
// is cleared so a future event can retry fresh.
func (c *Cache) fetchPluginWithRetry(slug, version string, attempt int) {
	backoffs := []time.Duration{1 * time.Minute, 5 * time.Minute, 15 * time.Minute, 1 * time.Hour}
	key := pluginKey(slug, version)

	checksums, err := FetchPluginChecksums(slug, version)
	if err == nil {
		c.setPluginChecksums(slug, version, checksums)
		c.mu.Lock()
		delete(c.fetching, key)
		c.mu.Unlock()
		fmt.Fprintf(os.Stderr, "wpcheck: cached %d checksums for plugin %s %s\n", len(checksums), slug, version)
		return
	}

	if attempt >= len(backoffs) {
		c.mu.Lock()
		delete(c.fetching, key)
		c.mu.Unlock()
		fmt.Fprintf(os.Stderr, "wpcheck: plugin fetch abandoned for %s %s after %d attempts: %v\n",
			slug, version, attempt+1, err)
		return
	}
	delay := backoffs[attempt]
	fmt.Fprintf(os.Stderr, "wpcheck: plugin fetch failed for %s %s, retry in %v: %v\n",
		slug, version, delay, err)
	time.AfterFunc(delay, func() {
		c.fetchPluginWithRetry(slug, version, attempt+1)
	})
}

// IsVerifiedPluginFile compares a file against the cached wordpress.org
// checksum for its plugin/version. Returns true only when the on-disk
// content hash matches. Triggers a background fetch on cache miss.
func (c *Cache) IsVerifiedPluginFile(fd int, path string) bool {
	root, slug := DetectPluginRoot(path)
	if root == "" {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return false
	}

	version, err := ReadPluginVersion(root, slug)
	if err != nil || version == "" {
		return false
	}

	expected, ok := c.lookupPluginChecksum(slug, version, rel)
	if !ok {
		if !c.hasPluginChecksums(slug, version) {
			c.startBackgroundPluginFetch(slug, version)
		}
		return false
	}

	data := make([]byte, maxFileSize)
	n, err := unix.Pread(fd, data, 0)
	if n <= 0 || (err != nil && n == 0) {
		return false
	}
	h := sha256.Sum256(data[:n])
	return hex.EncodeToString(h[:]) == expected
}
