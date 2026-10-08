package checks

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
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
	_ = db.UpdateFeeds()
	mu.Lock()
	defer mu.Unlock()
	for _, path := range fetched {
		if strings.HasSuffix(path, "/edrop.txt") {
			t.Fatalf("retired EDROP feed fetched: %v", fetched)
		}
	}
	if len(fetched) == 0 {
		t.Fatal("no feed fetched; the transport stub is not in use")
	}
}
