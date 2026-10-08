package checks

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Spamhaus merged EDROP into DROP and left edrop.txt holding only a notice.
// The feed downloaded nothing, failed its floor every day and kept serving
// its last cache forever, so ranges Spamhaus had since delisted stayed
// flagged. The feed is gone: its cache no longer loads and nothing fetches it.
func TestRetiredEDROPFeedIsNeitherLoadedNorFetched(t *testing.T) {
	dir := t.TempDir()
	var cached []string
	for i := 0; i < 16; i++ {
		cached = append(cached, fmt.Sprintf("198.51.100.%d/28", i*16))
	}
	if err := os.WriteFile(filepath.Join(dir, "spamhaus-edrop.txt"), []byte(strings.Join(cached, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db := &ThreatDB{badIPs: map[string]string{}, whitelist: map[string]bool{}, dbPath: dir}
	db.loadFeedCache()
	if source, found := db.Lookup("198.51.100.5"); found {
		t.Fatalf("retired EDROP cache still served (source %q)", source)
	}

	var mu sync.Mutex
	var fetched []string
	withDefaultHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetched = append(fetched, r.URL.Path)
		mu.Unlock()
		http.NotFound(w, r)
	}))
	if err := db.UpdateFeeds(); err == nil {
		t.Fatal("failed downloads reported a successful refresh")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range fetched {
		if strings.HasSuffix(path, "/edrop.txt") {
			t.Fatalf("retired EDROP feed fetched: %v", fetched)
		}
	}
	wantPaths := map[string]bool{
		"/drop/drop.txt":       true,
		"/lists/all.txt":       true,
		"/list/ci-badguys.txt": true,
	}
	if len(fetched) != len(wantPaths) {
		t.Fatalf("fetched %v, want exactly the three active feeds", fetched)
	}
	for _, path := range fetched {
		if !wantPaths[path] {
			t.Fatalf("unexpected or duplicate feed fetch: %q", path)
		}
		delete(wantPaths, path)
	}
	if _, exists := feedMinEntries["spamhaus-edrop"]; exists {
		t.Fatal("retired EDROP feed still has a validation floor")
	}
}

// Retiring a feed must not discard overlapping live coverage or local state.
func TestRetiredEDROPUpgradeKeepsActiveCoverage(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)
	db.AddPermanent("198.51.100.17", "operator block")
	db.AddWhitelist("198.51.100.7")

	retiredPath := filepath.Join(db.dbPath, "spamhaus-edrop.txt")
	var retiredLines []string
	for i := 0; i < 16; i++ {
		retiredLines = append(retiredLines, fmt.Sprintf("198.51.100.%d/28", i*16))
	}
	retired := strings.Join(retiredLines, "\n") + "\n"
	if err := os.WriteFile(retiredPath, []byte(retired), 0o600); err != nil {
		t.Fatal(err)
	}

	lines := map[string][]string{
		"spamhaus-drop": {"198.51.100.0/28"},
	}
	for i := 1; i < feedMinEntries["spamhaus-drop"]; i++ {
		lines["spamhaus-drop"] = append(lines["spamhaus-drop"], fmt.Sprintf("203.0.113.%d/32", i))
	}
	for i := 0; i < feedMinEntries["blocklist-de"]; i++ {
		lines["blocklist-de"] = append(lines["blocklist-de"], fmt.Sprintf("2001:db8:1::%x", i))
	}
	for i := 0; i < feedMinEntries["cins-army"]; i++ {
		lines["cins-army"] = append(lines["cins-army"], fmt.Sprintf("2001:db8:2::%x", i))
	}
	for name, entries := range lines {
		saveLines(filepath.Join(db.dbPath, name+".txt"), entries)
	}
	lastUpdate := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	if err := os.WriteFile(filepath.Join(db.dbPath, "last_update"), []byte(lastUpdate.Format(time.RFC3339)), 0o600); err != nil {
		t.Fatal(err)
	}

	assertCoverage := func(db *ThreatDB) {
		t.Helper()
		for ip, source := range map[string]string{
			"198.51.100.5":  "threat-feed-cidr",
			"198.51.100.17": "permanent-blocklist",
			"2001:db8:1::1": "blocklist-de",
			"2001:db8:2::1": "cins-army",
		} {
			if got, found := db.Lookup(ip); !found || got != source {
				t.Errorf("Lookup(%q) = (%q, %v), want (%q, true)", ip, got, found, source)
			}
		}
		for _, ip := range []string{"198.51.100.7", "198.51.100.33"} {
			if source, found := db.Lookup(ip); found {
				t.Errorf("whitelisted or retired-only IP %q still flagged by %q", ip, source)
			}
		}
		wantIPs := len(lines["blocklist-de"]) + len(lines["cins-army"])
		wantNets := len(lines["spamhaus-drop"])
		stats := db.Stats()
		for key, want := range map[string]int{
			"feed_ips": wantIPs, "feed_cidrs": wantNets,
			"total": wantIPs + wantNets + 1, "permanent_ips": 1, "whitelist": 1,
		} {
			if got := stats[key]; got != want {
				t.Errorf("Stats()[%q] = %v, want %d", key, got, want)
			}
		}
		if got, err := os.ReadFile(retiredPath); err != nil || string(got) != retired {
			t.Fatalf("ignored retired cache changed: %q (%v)", got, err)
		}
	}
	load := func() *ThreatDB {
		t.Helper()
		loaded := newTestThreatDB(t)
		loaded.dbPath = db.dbPath
		loaded.loadPermanentBlocklist()
		loaded.loadPersistedWhitelist()
		loaded.loadFeedCache()
		return loaded
	}
	loaded := load()
	assertCoverage(loaded)
	if !loaded.lastUpdate.Equal(lastUpdate) || loaded.FeedsStale() {
		t.Fatal("retired cache changed active-feed freshness or refresh throttle")
	}

	lines["spamhaus-drop"][1] = "203.0.113.200/32"
	lines["blocklist-de"][0] = "2001:db8:1::ffff"
	lines["cins-army"][0] = "2001:db8:2::ffff"
	bodyByPath := map[string]string{
		"/drop/drop.txt":       strings.Join(lines["spamhaus-drop"], "\n"),
		"/lists/all.txt":       strings.Join(lines["blocklist-de"], "\n"),
		"/list/ci-badguys.txt": strings.Join(lines["cins-army"], "\n"),
	}
	fetched := make(map[string]int)
	withDefaultHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched[r.URL.Path]++
		body, ok := bodyByPath[r.URL.Path]
		if !ok {
			t.Errorf("unexpected feed fetch: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	rewindFeedUpdateWindow(loaded)
	if err := loaded.UpdateFeeds(); err != nil {
		t.Fatal(err)
	}
	for path := range bodyByPath {
		if fetched[path] != 1 {
			t.Errorf("fetches for %q = %d, want 1", path, fetched[path])
		}
	}
	for _, refreshed := range []*ThreatDB{loaded, load()} {
		assertCoverage(refreshed)
		for _, ip := range []string{"203.0.113.200", "2001:db8:1::ffff", "2001:db8:2::ffff"} {
			if _, found := refreshed.Lookup(ip); !found {
				t.Errorf("new active-feed entry %q not applied", ip)
			}
		}
		for _, ip := range []string{"203.0.113.1", "2001:db8:1::0", "2001:db8:2::0"} {
			if source, found := refreshed.Lookup(ip); found {
				t.Errorf("withdrawn active-feed entry %q still flagged by %q", ip, source)
			}
		}
	}
}
