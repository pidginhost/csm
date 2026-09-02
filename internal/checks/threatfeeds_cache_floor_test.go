package checks

import (
	"os"
	"path/filepath"
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
	if err := os.WriteFile(filepath.Join(dir, "last_update"), []byte(time.Now().UTC().Format(time.RFC3339)), 0o600); err != nil {
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
	if !db.LastUpdated.IsZero() {
		t.Fatal("last update kept although a feed is incomplete; the next refresh would be skipped")
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
