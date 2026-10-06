package checks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"golang.org/x/sys/unix"
)

// statCountingOS records which directory entries had Info called, the lstat a
// walk of millions of files pays per name.
type statCountingOS struct {
	realOS
	mu             sync.Mutex
	stats          map[string]int
	regularChecked map[string]bool
	infoErr        error
}

type statCountingEntry struct {
	os.DirEntry
	owner *statCountingOS
}

func (e statCountingEntry) Info() (os.FileInfo, error) {
	e.owner.mu.Lock()
	e.owner.stats[e.Name()]++
	e.owner.mu.Unlock()
	if e.owner.infoErr != nil {
		return nil, e.owner.infoErr
	}
	info, err := e.DirEntry.Info()
	if err != nil {
		return nil, err
	}
	return statCountingInfo{FileInfo: info, name: e.Name(), owner: e.owner}, nil
}

type statCountingInfo struct {
	os.FileInfo
	name  string
	owner *statCountingOS
}

func (i statCountingInfo) Mode() os.FileMode {
	mode := i.FileInfo.Mode()
	i.owner.mu.Lock()
	defer i.owner.mu.Unlock()
	if i.owner.regularChecked == nil {
		i.owner.regularChecked = map[string]bool{}
	}
	i.owner.regularChecked[i.name] = mode.IsRegular()
	return mode
}

func (o *statCountingOS) Open(name string) (*os.File, error) {
	// A read before the walk checks the entry's regular-file mode must fail
	// the finding tests even if the reader itself checks the opened file.
	o.mu.Lock()
	checked := o.regularChecked[filepath.Base(name)]
	o.mu.Unlock()
	if !checked {
		return nil, os.ErrPermission
	}
	return o.realOS.Open(name)
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

func TestPhishingWalkPreservesCandidateFindings(t *testing.T) {
	for _, tc := range []struct {
		names    []string
		body     string
		zip      bool
		wantStat bool
		check    string
		severity alert.Severity
	}{
		{
			names:    []string{"verify.html", "VERIFY.HTML", "verify.htm", "VERIFY.HTM", "results.html"},
			body:     officePhishHTML + strings.Repeat(" ", 3500),
			wantStat: true,
			check:    "phishing_page",
			severity: alert.Critical,
		},
		{
			names:    []string{"embed.html", "EMBED.HTM"},
			body:     `<iframe src="https://evil.example/login" width="100%" height="100%"></iframe>`,
			wantStat: true,
			check:    "phishing_iframe",
			severity: alert.Critical,
		},
		{
			names: []string{
				"share.php", "SHARE.PHP", "share.php2", "share.php3", "share.php4",
				"share.php5", "share.php6", "share.php7", "share.php8", "share.phtml", "SHARE.PHT",
				"index.php4", "credentials.php",
			},
			body:     dropboxPhishPHP + strings.Repeat(" ", 3500),
			wantStat: true,
			check:    "phishing_php",
			severity: alert.Critical,
		},
		{
			names:    []string{"go.php", "GO.PHP", "go.php8", "GO.PHTML", "go.pht"},
			body:     `<?php header('Location: '.$_GET['url']);`,
			wantStat: true,
			check:    "phishing_redirector",
			severity: alert.High,
		},
		{
			names: []string{
				"results.txt", "RESULTS.TXT", "result.txt", "log.txt", "logs.txt", "emails.txt",
				"data.txt", "passwords.txt", "creds.txt", "credentials.txt", "victims.txt",
				"output.txt", "harvested.txt", "results.log", "emails.log", "data.log",
				"victims", "harvested.json", "credentials.dat", "creds.log", "stolen-data",
				"results.phps", "results.php.bak", "RESULTS.CSS", "victim.png",
			},
			body:     strings.Repeat("alice@example.com\n", 12),
			wantStat: true,
			check:    "phishing_credential_log",
			severity: alert.Critical,
		},
		{
			names:    []string{"results.csv", "emails.csv", "data.csv"},
			body:     strings.Repeat("alice@example.com\n", 12),
			wantStat: true,
		},
		{
			names:    []string{"office365.zip", "OFFICE365.ZIP", "paypal-results.zip", "secure-login.zip"},
			zip:      true,
			wantStat: true,
			check:    "phishing_kit_archive",
			severity: alert.High,
		},
		{
			names: []string{
				"index.php", "INDEX.PHP", "wp-login.php", "WP-CONFIG.PHP", "config.php",
				"wp-cron.php", "wp-settings.php", "wp-load.php", "wp-blog-header.php", "wp-links-opml.php",
				"xmlrpc.php", "wp-signup.php", "wp-activate.php", "wp-trackback.php", "wp-comments-post.php",
				"wp-mail.php", "settings.php", "configuration.php", "share.phps", "share.php9", "share.php.bak",
			},
			body: dropboxPhishPHP + strings.Repeat(" ", 3500),
		},
		{
			names: []string{"backup.zip", "results.zip", "credentials.zip", "login.zip", "secure.zip"},
			zip:   true,
		},
		{
			names: []string{"plain.txt", "style.css", "logo.png", "app.js", "README.md", "composer.lock"},
			body:  strings.Repeat("alice@example.com\n", 12),
		},
	} {
		for _, name := range tc.names {
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, name)
				if tc.zip {
					writeKitTestZip(t, path, []string{"kit/login.html", "kit/next.php", "kit/results.txt"})
				} else if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
					t.Fatal(err)
				}
				counting := &statCountingOS{stats: map[string]int{}}
				prev := osFS
				SetOS(counting)
				t.Cleanup(func() { SetOS(prev) })

				var findings []alert.Finding
				scanForPhishing(context.Background(), root, 1, "alice", &config.Config{}, &findings)
				wantStats := 0
				if tc.wantStat {
					wantStats = 1
				}
				if got := counting.stats[name]; got != wantStats {
					t.Errorf("stat calls = %d, want %d", got, wantStats)
				}
				if tc.check == "" {
					if len(findings) != 0 {
						t.Fatalf("unexpected findings: %+v", findings)
					}
					return
				}
				if len(findings) != 1 {
					t.Fatalf("findings = %+v, want one %s", findings, tc.check)
				}
				finding := findings[0]
				if finding.Check != tc.check || finding.Severity != tc.severity || finding.FilePath != path {
					t.Fatalf("finding = %+v, want %s (%s) at %s", finding, tc.check, tc.severity, path)
				}
			})
		}
	}
}

func TestPhishingWalkPreservesCandidateStatErrors(t *testing.T) {
	for _, name := range []string{"page.HTML", "share.PHP", "go.PHT", "RESULTS.CSS", "OFFICE365.ZIP"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, name), make([]byte, 4000), 0600); err != nil {
				t.Fatal(err)
			}
			counting := &phishingReadCountingOS{statCountingOS: &statCountingOS{
				stats: map[string]int{}, infoErr: os.ErrPermission,
			}}
			prev := osFS
			SetOS(counting)
			t.Cleanup(func() { SetOS(prev) })
			ctx, collector := withIncompleteCheckCollector(context.Background())
			var findings []alert.Finding
			scanForPhishing(ctx, root, 1, "alice", &config.Config{}, &findings)
			if counting.stats[name] != 1 || len(counting.reads) != 0 || len(findings) != 0 {
				t.Fatalf("stat failure: stats=%v reads=%v findings=%+v", counting.stats, counting.reads, findings)
			}
			if !collector.contains("phishing") {
				t.Fatal("candidate stat failure did not mark the check incomplete")
			}
		})
	}
}

type phishingReadCountingOS struct {
	*statCountingOS
	reads []string
}

func (o *phishingReadCountingOS) Open(name string) (*os.File, error) {
	o.reads = append(o.reads, name)
	return nil, os.ErrPermission
}

func TestPhishingWalkStatsNonRegularCandidatesBeforeReading(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"page.HTML", "share.PHP", "go.PHT", "RESULTS.TXT", "OFFICE365.ZIP"} {
				path := filepath.Join(root, name)
				var err error
				if kind == "symlink" {
					err = os.Symlink(filepath.Join(t.TempDir(), "target"), path)
				} else {
					err = unix.Mkfifo(path, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			counting := &phishingReadCountingOS{statCountingOS: &statCountingOS{stats: map[string]int{}}}
			prev := osFS
			SetOS(counting)
			t.Cleanup(func() { SetOS(prev) })
			ctx, collector := withIncompleteCheckCollector(context.Background())
			var findings []alert.Finding
			scanForPhishing(ctx, root, 1, "alice", &config.Config{}, &findings)
			if len(counting.stats) != 5 {
				t.Fatalf("stat calls = %v, want every non-regular candidate", counting.stats)
			}
			for name, calls := range counting.stats {
				if calls != 1 {
					t.Errorf("stat calls for %s = %d, want 1", name, calls)
				}
			}
			if len(counting.reads) != 0 {
				t.Fatalf("attempted to read non-regular candidates: %v", counting.reads)
			}
			if len(findings) != 0 || collector.contains("phishing") {
				t.Fatalf("non-regular candidates produced findings or marked the check incomplete: %+v", findings)
			}
		})
	}
}
