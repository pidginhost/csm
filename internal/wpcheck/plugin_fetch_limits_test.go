package wpcheck

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPluginFetchDropsExpiredNotFoundHistory(t *testing.T) {
	c, _ := boundedCoreFetchCache(t, http.StatusNotFound)
	c.markPluginNotFound("premium", "1.0", time.Hour)
	c.markPluginNotFound("elementor", "99.0.0", -time.Second)
	c.Verify(Verification{Kind: KindPlugin, Slug: "elementor", Version: "99.0.1"})
	waitForNotFetching(t, c, pluginKey("elementor", "99.0.1"))
	c.mu.RLock()
	_, retained := c.pluginNotFoundUntil[pluginKey("elementor", "99.0.0")]
	c.mu.RUnlock()
	if retained {
		t.Fatal("expired missing-release history survived a new fetch")
	}
	if !c.isPluginNotFound("premium", "1.0") {
		t.Fatal("pruning expired history removed a live not-found marker")
	}
}

func TestPluginFetchRetriesExpiredNotFoundRelease(t *testing.T) {
	c, hits := boundedCoreFetchCache(t, http.StatusNotFound)
	c.markPluginNotFound("elementor", "99.0.0", -time.Second)
	c.Verify(Verification{Kind: KindPlugin, Slug: "elementor", Version: "99.0.0"})
	waitForNotFetching(t, c, pluginKey("elementor", "99.0.0"))
	if got := hits.Load(); got != 1 {
		t.Fatalf("expired release made %d requests, want one", got)
	}
	if !c.isPluginNotFound("elementor", "99.0.0") {
		t.Fatal("new 404 did not renew the expired not-found marker")
	}
}

func TestPluginFetchDoesNotRestartCachedRelease(t *testing.T) {
	c, hits := boundedCoreFetchCache(t, http.StatusServiceUnavailable)
	c.setPluginChecksums("elementor", "3.30.0", map[string]string{
		"loader.php": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	// A fetch may finish after a caller's cache lookup but before admission.
	c.startBackgroundPluginFetch("elementor", "3.30.0")
	if isFetching(c, pluginKey("elementor", "3.30.0")) {
		t.Fatal("cached release started another fetch/retry chain")
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("cached release made %d requests, want none", got)
	}
}

func TestPluginFetchDedupesConcurrentNotFound(t *testing.T) {
	c, hits := boundedCoreFetchCache(t, http.StatusNotFound)
	for i := range 20 {
		version := fmt.Sprintf("99.0.%d", i)
		before := hits.Load()
		var callers sync.WaitGroup
		for range 64 {
			callers.Go(func() { c.startBackgroundPluginFetch("elementor", version) })
		}
		callers.Wait()
		waitForNotFetching(t, c, pluginKey("elementor", version))
		if got := hits.Load() - before; got != 1 {
			t.Fatalf("concurrent misses for %s made %d requests, want one", version, got)
		}
	}
}

// A fleet-wide update wave installs many distinct plugin releases within an
// hour. Realtime verification of their stock files depends on each release's
// manifest arriving, so plugin fetches must not be rationed by the small
// budget that bounds tenant-named core releases.
func TestPluginUpdateWaveIsNotRationedByCoreFetchBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slug, _, _ := strings.Cut(path.Base(r.URL.Path), ".")
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, err := zw.Create(slug + "/" + slug + ".php")
		if err == nil {
			_, _ = f.Write([]byte("<?php\n/* Plugin Name: " + slug + "\nVersion: 1.0\n*/\n"))
		}
		_ = zw.Close()
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)
	withTestHTTPClient(t, srv)
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	c := NewCache(t.TempDir())
	stop := make(chan struct{})
	c.SetStopCh(stop)
	t.Cleanup(func() { close(stop) })

	const releases = 100
	deadline := time.Now().Add(10 * time.Second)
	for {
		missing := 0
		for i := range releases {
			slug := fmt.Sprintf("plugin%d", i)
			// Each pass is another file event of that release.
			c.Verify(Verification{Kind: KindPlugin, Slug: slug, Version: "1.0"})
			if !c.hasPluginChecksums(slug, "1.0") {
				missing++
			}
		}
		if missing == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d plugin releases never got their manifest", missing, releases)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
