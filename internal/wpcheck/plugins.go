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

// ErrPluginNotInWPOrg is returned when wordpress.org responds with HTTP 404
// for a plugin slug+version. Plugins that are not in the wp.org repository
// (paid forks, custom internal plugins, slugs that simply do not exist) need
// to be distinguished from transient errors so the cache can suppress
// further fetch attempts for a TTL.
//
// 5xx responses, network errors, and malformed responses are NOT this
// error - those keep their normal retry behaviour because the plugin may
// still exist in the catalogue and wp.org may simply be having an outage.
var ErrPluginNotInWPOrg = errors.New("plugin not in wordpress.org repository")

func fetchPluginChecksumsFromURL(url, slug string) (map[string]string, error) {
	resp, err := httpClient.Get(url) //nolint:gosec,bodyclose // httpClient has a timeout; body is closed below.
	if err != nil {
		return nil, fmt.Errorf("plugin zip GET failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("plugin zip HTTP 404 from %s: %w", url, ErrPluginNotInWPOrg)
	}
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

// pluginNotFoundTTL bounds how long a wp.org 404 outcome suppresses
// re-fetches for the same slug+version. After expiry the next cache miss
// retries normally, so a plugin that wp.org publishes later will be
// picked up. 72 hours strikes a balance between not flooding wp.org with
// requests for non-existent plugins and propagating corrections in
// reasonable time.
const pluginNotFoundTTL = 72 * time.Hour

// markPluginNotFound records a wp.org 404 outcome so subsequent fetches
// short-circuit until ttl elapses. Caller passes ttl explicitly so tests
// can shorten or invert it; production code should use pluginNotFoundTTL.
func (c *Cache) markPluginNotFound(slug, version string, ttl time.Duration) {
	key := pluginKey(slug, version)
	c.mu.Lock()
	if c.pluginNotFoundUntil == nil {
		c.pluginNotFoundUntil = make(map[string]time.Time)
	}
	c.pluginNotFoundUntil[key] = time.Now().Add(ttl)
	c.mu.Unlock()
}

// isPluginNotFound reports whether an unexpired wp.org 404 marker exists
// for slug+version. Markers are scoped to slug+version so a fork of a
// plugin under a new version number that DOES exist on wp.org is still
// fetched.
func (c *Cache) isPluginNotFound(slug, version string) bool {
	key := pluginKey(slug, version)
	c.mu.RLock()
	until, ok := c.pluginNotFoundUntil[key]
	c.mu.RUnlock()
	if !ok {
		return false
	}
	return time.Now().Before(until)
}

func (c *Cache) startBackgroundPluginFetch(slug, version string) {
	// wp.org has already told us this slug+version does not exist;
	// suppress the fetch entirely until the marker expires. Without this
	// gate every cache miss for a non-wp.org plugin would re-arm the
	// 4-attempt retry cycle.
	if c.isPluginNotFound(slug, version) {
		return
	}
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
//
// Special case: an HTTP 404 from wordpress.org is treated as a definitive
// "this plugin is not in the wp.org repository" signal. We mark the
// slug+version not-found for pluginNotFoundTTL and skip the retry cycle
// entirely. Network errors and 5xx responses keep their normal retry
// behaviour - those are transient.
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

	if errors.Is(err, ErrPluginNotInWPOrg) {
		c.markPluginNotFound(slug, version, pluginNotFoundTTL)
		c.mu.Lock()
		delete(c.fetching, key)
		c.mu.Unlock()
		fmt.Fprintf(os.Stderr, "wpcheck: plugin %s %s not in wp.org repository, suppressing retries for %s\n",
			slug, version, pluginNotFoundTTL)
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
