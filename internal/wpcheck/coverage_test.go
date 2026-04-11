package wpcheck

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- FetchChecksums + httpClient override ------------------------------

// withTestHTTPClient temporarily redirects the package's httpClient to a
// server-backed client. Restores the default on cleanup.
func withTestHTTPClient(t *testing.T, srv *httptest.Server) {
	t.Helper()
	orig := httpClient
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = orig })
}

func TestFetchChecksumsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := map[string]any{
			"checksums": map[string]string{
				"wp-admin/index.php":       "abcdef0123456789abcdef0123456789",
				"wp-includes/version.php":  "1111111111111111eeeeeeeeeeeeeeee",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)

	// Redirect the package's checksumAPIURL target to our httptest server
	// by overriding the base URL via wrapping: we temporarily monkey-patch
	// by swapping the httpClient transport to rewrite the request URL.
	origTransport := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origTransport })

	raw, sums, err := FetchChecksums("6.5.2", "en_US")
	if err != nil {
		t.Fatalf("FetchChecksums: %v", err)
	}
	if len(raw) == 0 {
		t.Error("raw body should not be empty")
	}
	if len(sums) != 2 {
		t.Errorf("got %d checksums, want 2", len(sums))
	}
	if sums["wp-admin/index.php"] != "abcdef0123456789abcdef0123456789" {
		t.Errorf("checksum mismatch for wp-admin/index.php: %q", sums["wp-admin/index.php"])
	}
}

type rewriteTransport struct {
	target string
	inner  http.RoundTripper
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the host with the test server's host but keep the path+query.
	parsed, err := req.URL.Parse(t.target)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme = parsed.Scheme
	req.URL.Host = parsed.Host
	req.Host = parsed.Host
	return t.inner.RoundTrip(req)
}

func TestFetchChecksumsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	_, _, err := FetchChecksums("6.5.2", "en_US")
	if err == nil {
		t.Fatal("non-200 should error")
	}
	if !strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("error = %v, want HTTP 503 in message", err)
	}
}

func TestFetchChecksumsBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not json"))
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	_, _, err := FetchChecksums("6.5.2", "en_US")
	if err == nil {
		t.Fatal("bad JSON should error")
	}
}

func TestFetchChecksumsDialFailure(t *testing.T) {
	// Override transport with one that always fails to simulate a network
	// error (unreachable WP API).
	orig := httpClient.Transport
	httpClient.Transport = errTransport{}
	t.Cleanup(func() { httpClient.Transport = orig })

	_, _, err := FetchChecksums("6.5.2", "en_US")
	if err == nil {
		t.Fatal("dial failure should error")
	}
	if !strings.Contains(err.Error(), "HTTP request failed") {
		t.Errorf("error = %v, want HTTP request failed", err)
	}
}

type errTransport struct{}

func (errTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &httpError{msg: "simulated dial failure"}
}

type httpError struct{ msg string }

func (e *httpError) Error() string { return e.msg }

// --- Cache.loadFromDisk, PersistChecksums ------------------------------

func TestNewCacheMissingStateDirReturnsEmpty(t *testing.T) {
	c := NewCache(filepath.Join(t.TempDir(), "nonexistent"))
	if c == nil {
		t.Fatal("NewCache should not return nil")
	}
	if len(c.checksums) != 0 {
		t.Errorf("expected empty checksums, got %d entries", len(c.checksums))
	}
}

func TestNewCacheLoadsExistingDiskCache(t *testing.T) {
	state := t.TempDir()
	wpDir := filepath.Join(state, "wp-checksums")
	if err := os.MkdirAll(wpDir, 0755); err != nil {
		t.Fatal(err)
	}
	payload := `{"checksums":{"wp-admin/index.php":"deadbeefdeadbeefdeadbeefdeadbeef"}}`
	if err := os.WriteFile(filepath.Join(wpDir, "6.5.2_en_US.json"), []byte(payload), 0644); err != nil {
		t.Fatal(err)
	}
	// Plus some junk to exercise the skip branches.
	if err := os.WriteFile(filepath.Join(wpDir, "not-json.txt"), []byte("junk"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(wpDir, "subdir.json"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wpDir, "malformed.json"), []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wpDir, "onepart.json"), []byte(payload), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCache(state)
	md5, ok := c.lookupChecksum("6.5.2", "en_US", "wp-admin/index.php")
	if !ok {
		t.Fatal("expected checksum to be loaded from disk")
	}
	if md5 != "deadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("md5 = %q", md5)
	}
}

func TestPersistChecksumsRoundTrip(t *testing.T) {
	state := t.TempDir()
	c := NewCache(state)
	raw := []byte(`{"checksums":{"a":"x"}}`)
	sums := map[string]string{"a": "x"}
	if err := c.PersistChecksums("6.5.2", "en_US", raw, sums); err != nil {
		t.Fatalf("PersistChecksums: %v", err)
	}
	// Verify on-disk file.
	diskPath := filepath.Join(state, "wp-checksums", "6.5.2_en_US.json")
	onDisk, err := os.ReadFile(diskPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != string(raw) {
		t.Errorf("on-disk mismatch: %q", onDisk)
	}
	// Verify in-memory cache populated.
	if got, ok := c.lookupChecksum("6.5.2", "en_US", "a"); !ok || got != "x" {
		t.Errorf("cache lookup failed: got=%q ok=%v", got, ok)
	}
	// Verify no leftover .tmp.
	if _, err := os.Stat(diskPath + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("leftover tmp file: %v", err)
	}
}

func TestPersistChecksumsFailsOnUnwritableState(t *testing.T) {
	// Create a file (not a dir) at the state path so MkdirAll fails.
	state := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(state, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	c := &Cache{
		statePath: state,
		checksums: make(map[string]map[string]string),
		roots:     make(map[string]rootEntry),
		fetching:  make(map[string]bool),
	}
	err := c.PersistChecksums("6.5.2", "en_US", []byte(`{}`), nil)
	if err == nil {
		t.Fatal("PersistChecksums should fail when state is a file")
	}
	if !strings.Contains(err.Error(), "creating wp-checksums dir") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- fetchWithRetry happy path -----------------------------------------
//
// Note: the retry branch (fetchWithRetry on error) is intentionally not
// exercised here because it schedules a time.AfterFunc timer with a
// 1-minute minimum backoff that cannot be cancelled from the test.
// Covering it without a code change would either require waiting 60+
// seconds for the timer to fire (unreliable + slow) or leaking a
// goroutine across the test boundary (not production-grade).
// See the remediation plan in the summary at end of this batch.

func TestFetchWithRetrySuccessPopulatesCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"checksums":{"wp-admin/index.php":"deadbeefdeadbeefdeadbeefdeadbeef"}}`))
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	state := t.TempDir()
	c := NewCache(state)
	// Mark as in-flight first — fetchWithRetry should clear it on success.
	key := cacheKey("6.5.2", "en_US")
	c.mu.Lock()
	c.fetching[key] = true
	c.mu.Unlock()

	c.fetchWithRetry("6.5.2", "en_US", 0)

	// Cache populated.
	if got, ok := c.lookupChecksum("6.5.2", "en_US", "wp-admin/index.php"); !ok || got != "deadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("lookup after fetchWithRetry success: got=%q ok=%v", got, ok)
	}
	// In-flight flag cleared.
	c.mu.RLock()
	inFlight := c.fetching[key]
	c.mu.RUnlock()
	if inFlight {
		t.Error("fetchWithRetry success should clear in-flight flag")
	}
	// On-disk cache persisted.
	if _, err := os.Stat(filepath.Join(state, "wp-checksums", "6.5.2_en_US.json")); err != nil {
		t.Errorf("on-disk cache not persisted: %v", err)
	}
}

// --- startBackgroundFetch dedupe ---------------------------------------

func TestStartBackgroundFetchDedupesInFlight(t *testing.T) {
	state := t.TempDir()
	c := NewCache(state)
	// Pre-mark as fetching — the second call should be a no-op.
	c.mu.Lock()
	c.fetching[cacheKey("6.5.2", "en_US")] = true
	c.mu.Unlock()

	// Second call returns immediately without launching a goroutine.
	c.startBackgroundFetch("6.5.2", "en_US")

	// The map still has exactly one "fetching" entry; no new goroutine
	// kicked off. (We can't directly observe goroutines but the dedup
	// branch is now covered.)
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.fetching[cacheKey("6.5.2", "en_US")] {
		t.Error("fetching flag was cleared by the dedupe branch")
	}
}

// --- RelativePath / ReadVersionFile error paths ------------------------

func TestRelativePathRejectsPathOutsideRoot(t *testing.T) {
	got := RelativePath("/var/www/html", "/etc/passwd")
	if got != "" {
		t.Errorf("RelativePath outside root = %q, want empty", got)
	}
}

func TestRelativePathInsideRoot(t *testing.T) {
	got := RelativePath("/var/www/html", "/var/www/html/wp-admin/index.php")
	if got != filepath.Join("wp-admin", "index.php") {
		t.Errorf("RelativePath = %q", got)
	}
}

func TestReadVersionFileMissingFile(t *testing.T) {
	_, _, err := ReadVersionFile(t.TempDir())
	if err == nil {
		t.Fatal("ReadVersionFile on empty dir should error")
	}
}

func TestReadVersionFileSuccess(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "wp-includes"), 0755); err != nil {
		t.Fatal(err)
	}
	content := `<?php
$wp_version = '6.5.2';
$wp_local_package = 'fr_FR';
`
	if err := os.WriteFile(filepath.Join(root, "wp-includes", "version.php"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	version, locale, err := ReadVersionFile(root)
	if err != nil {
		t.Fatal(err)
	}
	if version != "6.5.2" {
		t.Errorf("version = %q", version)
	}
	if locale != "fr_FR" {
		t.Errorf("locale = %q", locale)
	}
}

// --- IsVerifiedCoreFile edge branches ----------------------------------

func TestIsVerifiedCoreFileNonWPPathReturnsFalse(t *testing.T) {
	c := NewCache(t.TempDir())
	// Path with no wp-includes/wp-admin markers: DetectWPRoot returns "".
	// fd=0 is stdin and unused because we short-circuit before Pread.
	if c.IsVerifiedCoreFile(0, "/tmp/not-a-wp/file.php") {
		t.Error("non-WP path should return false")
	}
}

func TestIsVerifiedCoreFileMissingVersionFileReturnsFalse(t *testing.T) {
	// Genuine wp-includes marker in path but no version.php on disk.
	dir := t.TempDir()
	root := filepath.Join(dir, "site", "public_html")
	if err := os.MkdirAll(filepath.Join(root, "wp-includes"), 0755); err != nil {
		t.Fatal(err)
	}
	bogus := filepath.Join(root, "wp-includes", "load.php")
	if err := os.WriteFile(bogus, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(bogus)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	c := NewCache(t.TempDir())
	if c.IsVerifiedCoreFile(int(f.Fd()), bogus) {
		t.Error("missing version.php should return false")
	}
}

func TestIsVerifiedCoreFileNoCachedChecksumsReturnsFalse(t *testing.T) {
	// WP root with valid version.php, but no checksums cached — triggers
	// startBackgroundFetch and returns false. We use an httptest server
	// that returns a permanent error so the background fetch doesn't
	// persist anything, but it also schedules a retry (see note about
	// retry branch above). Use an empty cache state and rely on the
	// in-flight dedupe flag to keep things quiet.
	dir := t.TempDir()
	root := filepath.Join(dir, "public_html")
	if err := os.MkdirAll(filepath.Join(root, "wp-includes"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, "wp-includes", "version.php"),
		[]byte("<?php\n$wp_version = '6.5.2';\n"),
		0644,
	); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(root, "wp-includes", "load.php")
	if err := os.WriteFile(probe, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(probe)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	c := NewCache(t.TempDir())
	// Pre-mark as in-flight so startBackgroundFetch is a no-op — prevents
	// a real goroutine from spawning.
	c.mu.Lock()
	c.fetching[cacheKey("6.5.2", "en_US")] = true
	c.mu.Unlock()

	if c.IsVerifiedCoreFile(int(f.Fd()), probe) {
		t.Error("no cached checksums should return false")
	}
}

// --- DetectWPRoot extra coverage ---------------------------------------

func TestDetectWPRootIndexPhpAtRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "wp-includes"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-includes", "version.php"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	got := DetectWPRoot(filepath.Join(root, "index.php"))
	if got != root {
		t.Errorf("DetectWPRoot = %q, want %q", got, root)
	}
}

func TestDetectWPRootIndexPhpWithoutVersionPhpNotWP(t *testing.T) {
	// A random index.php with no wp-includes/version.php alongside is
	// NOT a WordPress root.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := DetectWPRoot(filepath.Join(root, "index.php")); got != "" {
		t.Errorf("DetectWPRoot of standalone index.php = %q, want empty", got)
	}
}

func TestDetectWPRootDirectoryMarker(t *testing.T) {
	// File directly inside /wp-includes/ via base dir detection.
	got := DetectWPRoot("/var/www/html/wp-includes/load.php")
	if got != "/var/www/html" {
		t.Errorf("DetectWPRoot = %q, want /var/www/html", got)
	}
}
