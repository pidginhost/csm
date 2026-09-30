package wpcheck

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"
)

func TestPluginFetchDropsExpiredNotFoundHistory(t *testing.T) {
	c, _ := boundedCoreFetchCache(t, http.StatusNotFound)
	c.markPluginNotFound("elementor", "99.0.0", -time.Second)
	c.Verify(Verification{Kind: KindPlugin, Slug: "elementor", Version: "99.0.1"})
	waitForNotFetching(t, c, pluginKey("elementor", "99.0.1"))
	c.mu.RLock()
	_, retained := c.pluginNotFoundUntil[pluginKey("elementor", "99.0.0")]
	c.mu.RUnlock()
	if retained {
		t.Fatal("expired missing-release history survived a new fetch")
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
