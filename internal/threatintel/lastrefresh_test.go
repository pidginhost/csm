package threatintel

import (
	"net"
	"path/filepath"
	"testing"
)

// The last-refresh time must survive a restart: the web UI reads it to show
// when the AI-crawler ranges were last fetched, so it has to come from the
// persisted cache, not just live process state.
func TestLastFetchedRangesRefresh_PersistsThroughCache(t *testing.T) {
	t.Cleanup(func() { PublishFetchedRanges(nil); setLastRefreshUnix(0) })

	setLastRefreshUnix(0)
	if !LastFetchedRangesRefresh().IsZero() {
		t.Fatal("last refresh should be zero before any refresh")
	}

	_, n, err := net.ParseCIDR("18.97.9.96/29")
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(t.TempDir(), "botranges.json")
	if err := SaveFetchedRanges(cachePath, map[string][]*net.IPNet{"perplexitybot": {n}}); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Simulate a fresh process: clear in-memory state, then load from cache.
	setLastRefreshUnix(0)
	if err := LoadFetchedRanges(cachePath); err != nil {
		t.Fatalf("load: %v", err)
	}
	if LastFetchedRangesRefresh().IsZero() {
		t.Fatal("last refresh should be set after loading a stamped cache")
	}
}
