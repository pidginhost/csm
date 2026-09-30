package wpcheck

import (
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A copy's installed-plugin header is account writable. Repeated writes must
// share the core checksum fetch budget even when each header names a new release.
func TestPluginFetchSharesConcurrentBudget(t *testing.T) {
	c, _ := boundedCoreFetchCache(t, http.StatusServiceUnavailable)
	for i := range 4 {
		c.Verify(Verification{Kind: KindCore, Version: fmt.Sprintf("99.0.%d", i), Locale: "en_US", Staged: true})
	}
	var callers sync.WaitGroup
	for i := range 64 {
		callers.Go(func() {
			c.Verify(Verification{Kind: KindPlugin, Slug: "elementor", Version: fmt.Sprintf("99.0.%d", i)})
		})
	}
	callers.Wait()
	c.mu.RLock()
	pending := len(c.fetching)
	c.mu.RUnlock()
	if pending != 8 {
		t.Fatalf("pending core/plugin fetch chains = %d, want 8", pending)
	}
}

func TestPluginFetchBoundsRepeatedHeaderChanges(t *testing.T) {
	c, hits := boundedCoreFetchCache(t, http.StatusNotFound)
	root := filepath.Join(t.TempDir(), "wp-content", "plugins", "elementor")
	for i := range 65 {
		version := fmt.Sprintf("99.0.%d", i)
		writeStaged(t, filepath.Join(root, "elementor.php"), "<?php\n/* Plugin Name: Elementor\nVersion: "+version+"\n*/\n")
		v := c.Describe(filepath.Join(root, "modules", "safe-mode", "mu-plugin", "elementor-safe-mode.php"))
		if v.Kind != KindPlugin || v.Slug != "elementor" || v.Version != version {
			t.Fatalf("description = %+v, want recorded Elementor release %s", v, version)
		}
		waitForNotFetching(t, c, pluginKey("elementor", version))
	}
	if got := hits.Load(); got != 64 {
		t.Fatalf("requests after repeated header changes = %d, want 64", got)
	}
	// Refusing a fetch leaves the copy unverified; cached proof still works.
	c.setPluginChecksums("elementor", "3.30.0", map[string]string{"loader.php": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if got := c.Verify(Verification{Kind: KindPlugin, Slug: "elementor", Version: "3.30.0", Rel: "loader.php",
		Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); got != VerdictVerified {
		t.Fatalf("cached proof during fetch throttling = %v, want verified", got)
	}
	c.mu.Lock()
	for key := range c.coreFetchAfter {
		c.coreFetchAfter[key] = time.Now().Add(-time.Second)
	}
	c.mu.Unlock()
	c.Verify(Verification{Kind: KindPlugin, Slug: "elementor", Version: "99.0.64"})
	waitForNotFetching(t, c, pluginKey("elementor", "99.0.64"))
	if got := hits.Load(); got != 65 {
		t.Fatalf("requests after budget expiry = %d, want 65", got)
	}
}

func TestPluginFetchExhaustionKeepsCooldown(t *testing.T) {
	c, hits := boundedCoreFetchCache(t, http.StatusServiceUnavailable)
	key := pluginKey("elementor", "99.0.1")
	c.fetching[key] = true
	c.fetchPluginWithRetry("elementor", "99.0.1", 4)
	c.Verify(Verification{Kind: KindPlugin, Slug: "elementor", Version: "99.0.1"})
	waitForNotFetching(t, c, key)
	if got := hits.Load(); got != 1 {
		t.Fatalf("requests after exhausting retries = %d, want 1", got)
	}
}

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
