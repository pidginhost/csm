package checks

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The download path refuses a feed below its minimum entry count, but the
// cache loader accepted whatever was on disk. A feed cache truncated by a
// crash mid-write (the writer truncated in place) was served, and because
// last_update was intact the next refresh was skipped for up to 20 hours.
// A cached feed below its floor counts as absent and forces a refresh.
func TestLoadFeedCacheTreatsTruncatedFeedAsAbsent(t *testing.T) {
	dir := t.TempDir()
	lastSuccess := time.Now().Add(-8 * 24 * time.Hour).UTC()
	if err := os.WriteFile(filepath.Join(dir, "last_update"), []byte(lastSuccess.Format(time.RFC3339)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blocklist-de.txt"), []byte("198.51.100.1\n198.51.100.2\n198.51.100.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db := &ThreatDB{badIPs: map[string]string{}, whitelist: map[string]bool{}, dbPath: dir}
	db.loadFeedCache()

	if n := len(db.feedIPs["blocklist-de"]); n != 0 {
		t.Fatalf("truncated feed served with %d entries; floor is %d", n, feedMinEntries["blocklist-de"])
	}
	if !db.lastUpdate.IsZero() {
		t.Fatal("refresh throttle kept although a feed is incomplete")
	}
	if db.LastUpdated.IsZero() {
		t.Fatal("last successful update was erased, so stale-feed health cannot alert")
	}
	if !db.FeedsStale() {
		t.Fatal("truncated cache suppressed the stale-feed health condition")
	}
}

func TestUpdateFeedsRejectsFreshFeedBelowFloor(t *testing.T) {
	withDefaultHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.1\n203.0.113.2\n203.0.113.3\n"))
	}))

	oldFeeds, oldFloors := threatFeeds, feedMinEntries
	threatFeeds = []struct {
		name string
		url  string
	}{{name: "test-feed", url: localHTTPTestURL}}
	feedMinEntries = map[string]int{"test-feed": 4}
	t.Cleanup(func() {
		threatFeeds = oldFeeds
		feedMinEntries = oldFloors
	})

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "test-feed.txt")
	cached := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"}
	saveLines(cachePath, cached)
	db := &ThreatDB{
		badIPs:    map[string]string{},
		whitelist: map[string]bool{},
		dbPath:    dir,
	}
	db.loadFeedCache()
	db.lastUpdate = time.Time{}

	if err := db.UpdateFeeds(); err == nil {
		t.Fatal("below-floor live feed was accepted")
	}
	if source, found := db.Lookup(cached[0]); !found || source != "test-feed" {
		t.Fatalf("good cached feed was replaced: source=%q found=%v", source, found)
	}
	got, err := os.ReadFile(cachePath)
	if err != nil || strings.TrimSpace(string(got)) != strings.Join(cached, "\n") {
		t.Fatalf("cache changed after below-floor fetch: %q (%v)", got, err)
	}
}

// saveLines replaces the cache atomically: a reader never sees a partial file
// and no temporary file is left behind.
func TestSaveLinesIsAtomicAndSorted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saveLines(path, []string{"198.51.100.9", "198.51.100.1"})
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "198.51.100.1\n198.51.100.9\n" {
		t.Fatalf("feed cache = %q (%v)", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}
