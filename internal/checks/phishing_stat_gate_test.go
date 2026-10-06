package checks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// statCountingOS records which directory entries had Info called, the lstat a
// walk of millions of files pays per name.
type statCountingOS struct {
	realOS
	mu    sync.Mutex
	stats map[string]int
}

type statCountingEntry struct {
	os.DirEntry
	owner *statCountingOS
}

func (e statCountingEntry) Info() (os.FileInfo, error) {
	e.owner.mu.Lock()
	e.owner.stats[e.Name()]++
	e.owner.mu.Unlock()
	return e.DirEntry.Info()
}

func (o *statCountingOS) ReadDir(name string) ([]os.DirEntry, error) {
	entries, err := o.realOS.ReadDir(name)
	for i, entry := range entries {
		entries[i] = statCountingEntry{DirEntry: entry, owner: o}
	}
	return entries, err
}

// The phishing walk stats only names one of its checks can judge; every other
// file is skipped on its name alone. The findings stay the same.
func TestPhishingWalkStatsOnlyCandidateNames(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"style.css":           "body{}",
		"logo.png":            "png",
		"app.js":              "var a=1;",
		"README.md":           "# readme",
		"index.php":           "<?php echo 1;",
		"composer.lock":       "{}",
		"backup.zip":          "zip",
		"page.html":           "<html></html>",
		"redirect.php":        "<?php header('Location: '.$_GET['u']);",
		"passwords.txt":       "user@example.com:hunter2\n",
		"office365-login.zip": "zip",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	counting := &statCountingOS{stats: map[string]int{}}
	prev := osFS
	SetOS(counting)
	t.Cleanup(func() { SetOS(prev) })

	var findings []alert.Finding
	scanForPhishing(context.Background(), root, 3, "alice", &config.Config{}, &findings)

	var stated []string
	for name := range counting.stats {
		stated = append(stated, name)
	}
	sort.Strings(stated)
	want := []string{"office365-login.zip", "page.html", "passwords.txt", "redirect.php"}
	if len(stated) != len(want) {
		t.Fatalf("stat calls = %v, want only %v", stated, want)
	}
	for i := range want {
		if stated[i] != want[i] {
			t.Fatalf("stat calls = %v, want only %v", stated, want)
		}
	}
}
