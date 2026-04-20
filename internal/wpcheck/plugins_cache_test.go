package wpcheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
