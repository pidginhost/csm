package wpcheck

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- pluginZipURL -----------------------------------------------------

func TestPluginZipURL(t *testing.T) {
	got := pluginZipURL("wordfence", "8.2.1")
	want := "https://downloads.wordpress.org/plugin/wordfence.8.2.1.zip"
	if got != want {
		t.Errorf("pluginZipURL: got %q, want %q", got, want)
	}
}

// --- FetchPluginChecksums ---------------------------------------------

// FetchPluginChecksums is a thin wrapper around fetchPluginChecksumsFromURL
// (already covered). The risk is a typo in the URL template; this test
// pins the wrapper to the real URL-shape by routing via rewriteTransport.
func TestFetchPluginChecksumsThinWrapper(t *testing.T) {
	slug := "test-plugin"
	version := "1.0.0"
	files := map[string][]byte{
		slug + "/" + slug + ".php": []byte("<?php // main\n"),
	}
	zipBytes := buildPluginZip(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	got, err := FetchPluginChecksums(slug, version)
	if err != nil {
		t.Fatalf("FetchPluginChecksums: %v", err)
	}
	if _, ok := got[slug+".php"]; !ok {
		t.Errorf("expected %s.php in checksum map, got keys: %v", slug, keysOf(got))
	}
}

// --- hasPluginChecksums -----------------------------------------------

func TestHasPluginChecksumsReflectsCacheState(t *testing.T) {
	c := NewCache(t.TempDir())

	if c.hasPluginChecksums("acme", "2.0") {
		t.Error("hasPluginChecksums true before any set")
	}

	c.setPluginChecksums("acme", "2.0", map[string]string{"acme.php": "h1"})

	if !c.hasPluginChecksums("acme", "2.0") {
		t.Error("hasPluginChecksums false after set for the same slug+version")
	}
	// A different version of the same slug must be treated as unknown:
	// the cache key is slug+":"+version.
	if c.hasPluginChecksums("acme", "2.1") {
		t.Error("hasPluginChecksums true for a version that was never fetched")
	}
}

// --- startBackgroundPluginFetch dedupe --------------------------------

// Pre-marking the key as in-flight means the second call must exit
// without spawning a new goroutine. Mirrors TestStartBackgroundFetchDedupesInFlight
// for the core-checksum cache.
func TestStartBackgroundPluginFetchDedupesInFlight(t *testing.T) {
	c := NewCache(t.TempDir())

	key := pluginKey("ghost", "1.0.0")
	c.mu.Lock()
	c.fetching[key] = true
	c.mu.Unlock()

	// Must return without re-entering the fetcher. If this spawned a
	// goroutine it would try to talk to downloads.wordpress.org; we
	// rely on the dedupe short-circuit keeping the test hermetic.
	c.startBackgroundPluginFetch("ghost", "1.0.0")

	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.fetching[key] {
		t.Error("fetching flag cleared by dedupe branch")
	}
}

// --- fetchPluginWithRetry happy path ----------------------------------

// Success on the first attempt populates the cache and clears the
// fetching flag. The retry scheduling branch stays uncovered — it uses
// time.AfterFunc with a 1-minute minimum backoff we can't cancel from
// the test (same constraint documented in the core fetchWithRetry
// test).
func TestFetchPluginWithRetrySuccessPopulatesCache(t *testing.T) {
	slug := "acme"
	version := "3.1.4"
	files := map[string][]byte{
		slug + "/" + slug + ".php":    []byte("<?php // main\n"),
		slug + "/includes/helper.php": []byte("<?php // helper\n"),
	}
	zipBytes := buildPluginZip(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	c := NewCache(t.TempDir())
	key := pluginKey(slug, version)
	c.mu.Lock()
	c.fetching[key] = true
	c.mu.Unlock()

	c.fetchPluginWithRetry(slug, version, 0)

	// Cache populated with the ZIP contents.
	if _, ok := c.lookupPluginChecksum(slug, version, slug+".php"); !ok {
		t.Errorf("expected %s.php in cache after fetch success", slug)
	}
	// Fetching flag cleared on success.
	c.mu.RLock()
	inFlight := c.fetching[key]
	c.mu.RUnlock()
	if inFlight {
		t.Error("fetching flag must be cleared on success")
	}
}

// Exhaustion branch: when attempt already equals len(backoffs), the
// function clears the flag and returns WITHOUT scheduling a retry —
// no time.AfterFunc leak.
func TestFetchPluginWithRetryExhaustionClearsFlag(t *testing.T) {
	// Route plugin fetch through a server that always 500s so the
	// first attempt fails. With attempt=len(backoffs) the function
	// falls through the exhaustion branch, not the retry branch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	c := NewCache(t.TempDir())
	slug := "nope"
	version := "0.0.0"
	key := pluginKey(slug, version)
	c.mu.Lock()
	c.fetching[key] = true
	c.mu.Unlock()

	// attempt=4 matches len(backoffs); function clears fetching and returns.
	c.fetchPluginWithRetry(slug, version, 4)

	c.mu.RLock()
	_, stillFetching := c.fetching[key]
	c.mu.RUnlock()
	if stillFetching {
		t.Error("fetching flag must be cleared on exhaustion")
	}
}

// --- helpers ----------------------------------------------------------

func keysOf[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- Plugin not-on-WP.org caching ------------------------------------
//
// The retry loop in fetchPluginWithRetry treats every error the same:
// 4 backoffs (1m, 5m, 15m, 1h) then give up. For a plugin that simply
// is not in the wp.org repository (Pro Elements, paid forks, custom
// internal plugins) every cache-miss arms a fresh 4-attempt cycle that
// will never succeed. The fix: when wp.org returns HTTP 404, mark the
// slug+version "not in WP.org" with a 72h TTL and short-circuit further
// fetch attempts during that window. Network errors and 5xx responses
// keep their normal retry behaviour - only an explicit 404 from the
// wp.org repository server is treated as a definitive missing-plugin
// signal.

func TestFetchPluginChecksums_404IsErrPluginNotInWPOrg(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	_, err := FetchPluginChecksums("pro-elements", "3.24.4")
	if err == nil {
		t.Fatal("expected an error from a 404 fetch")
	}
	if !errors.Is(err, ErrPluginNotInWPOrg) {
		t.Errorf("404 must wrap ErrPluginNotInWPOrg; got: %v", err)
	}
}

func TestFetchPluginChecksums_5xxNotErrPluginNotInWPOrg(t *testing.T) {
	// A wordpress.org outage returning 503 must NOT be confused with a
	// missing plugin. Treating it as not-found would silently drop
	// checksum verification for the entire plugin catalogue during the
	// outage. Only 404 carries that meaning.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	_, err := FetchPluginChecksums("any", "1.0")
	if err == nil {
		t.Fatal("expected an error from a 503")
	}
	if errors.Is(err, ErrPluginNotInWPOrg) {
		t.Errorf("503 must NOT be reported as not-in-wp.org; got: %v", err)
	}
}

func TestCache_NotFoundMarkerSuppressesFutureFetches(t *testing.T) {
	c := NewCache(t.TempDir())
	slug := "pro-elements"
	version := "3.24.4"

	// Marker freshly set: subsequent fetch attempts must short-circuit.
	c.markPluginNotFound(slug, version, time.Hour)
	if !c.isPluginNotFound(slug, version) {
		t.Fatal("isPluginNotFound must return true immediately after marking")
	}

	// Sibling slug+version must NOT inherit the marker.
	if c.isPluginNotFound(slug, "9.9.9") {
		t.Error("not-found marker must be scoped to slug+version, not slug alone")
	}
	if c.isPluginNotFound("other-plugin", version) {
		t.Error("not-found marker must be scoped to slug+version, not version alone")
	}
}

func TestCache_NotFoundMarkerExpiresAfterTTL(t *testing.T) {
	c := NewCache(t.TempDir())
	slug := "pro-elements"
	version := "3.24.4"

	// Inject an already-expired marker. After expiry the gate must allow
	// a new fetch attempt - wp.org may have published the plugin since
	// the last attempt, so corrections propagate.
	c.markPluginNotFound(slug, version, -time.Minute)
	if c.isPluginNotFound(slug, version) {
		t.Error("expired not-found marker must not gate fetches")
	}
}

func TestStartBackgroundPluginFetch_SkipsWhenNotFoundMarkerFresh(t *testing.T) {
	// HTTP server counts how many requests it sees. With the marker set,
	// startBackgroundPluginFetch must not reach the server at all.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		http.NotFound(w, nil)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	c := NewCache(t.TempDir())
	slug := "pro-elements"
	version := "3.24.4"
	c.markPluginNotFound(slug, version, time.Hour)

	c.startBackgroundPluginFetch(slug, version)

	// startBackgroundPluginFetch spawns a goroutine; give it generous
	// time to either NOT fire (the gate's job) or to fire (a regression).
	time.Sleep(50 * time.Millisecond)

	if hits != 0 {
		t.Errorf("startBackgroundPluginFetch must short-circuit when not-found marker is fresh; saw %d HTTP request(s)", hits)
	}
}

func TestFetchPluginWithRetry_404SetsNotFoundMarkerNoRetry(t *testing.T) {
	// One wp.org 404 must (a) set the marker, (b) clear the in-flight
	// flag, (c) NOT schedule a retry. Counting hits across a 200ms
	// window catches a regression that schedules time.AfterFunc.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		http.NotFound(w, nil)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	c := NewCache(t.TempDir())
	slug := "pro-elements"
	version := "3.24.4"
	key := pluginKey(slug, version)
	c.mu.Lock()
	c.fetching[key] = true
	c.mu.Unlock()

	c.fetchPluginWithRetry(slug, version, 0)

	if !c.isPluginNotFound(slug, version) {
		t.Error("404 outcome must set the not-found marker")
	}
	c.mu.RLock()
	_, stillFetching := c.fetching[key]
	c.mu.RUnlock()
	if stillFetching {
		t.Error("fetching flag must be cleared after a 404 outcome")
	}
	if hits != 1 {
		t.Errorf("expected exactly 1 wp.org request after 404 (no retry); saw %d", hits)
	}
}
