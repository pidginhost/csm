package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

type phpWriteOnlyOS struct {
	realOS
	path string
}

func (o phpWriteOnlyOS) Open(path string) (*os.File, error) {
	if path == o.path {
		return os.OpenFile(path, os.O_WRONLY, 0)
	}
	return o.realOS.Open(path)
}

// settlePHPCacheStamps moves the scan clock past the change-time window of
// the given files, which a test needs before it expects a clean read to be
// reusable. Chtimes cannot backdate change time, and sleeping it out costs a
// second per fixture. This does not advance the filesystem clock: tests that
// need a later write's ctime to differ must use swapPreservingMtime.
func settlePHPCacheStamps(t *testing.T, paths ...string) {
	t.Helper()
	settled := time.Now()
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if ctime := time.Unix(0, phpFileStampOf(info).Ctime); ctime.After(settled) {
			settled = ctime
		}
	}
	// Scans in this test start past the change-time window of every stamp
	// written so far, as if the files had been left alone for a while.
	start := settled.Add(time.Second + time.Millisecond)
	previous := phpContentNow
	phpContentNow = func() time.Time { return start }
	t.Cleanup(func() { phpContentNow = previous })
}

type phpNoIdentityInfo struct{ os.FileInfo }

func (phpNoIdentityInfo) Sys() any { return nil }

type phpNoIdentityOS struct{ realOS }

func (o phpNoIdentityOS) Stat(path string) (os.FileInfo, error) {
	info, err := o.realOS.Stat(path)
	if err != nil {
		return nil, err
	}
	return phpNoIdentityInfo{info}, nil
}

func TestPHPContentCacheRequiresFileIdentity(t *testing.T) {
	for _, content := range []string{phpCacheBenign, phpCacheMalicious} {
		t.Run(content, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "x.php")
			mtime := time.Unix(1700000000, 0)
			writePHPFixture(t, path, content, mtime)
			withMockOS(t, phpNoIdentityOS{})
			// A legacy entry must miss even when Stat cannot provide identity.
			scan := newPHPContentScan(&config.Config{}, phpContentCache{
				path: {Mtime: mtime.Unix(), Size: int64(len(content))},
			}, false)
			var findings []alert.Finding
			scan.scanFile(context.Background(), path, phpHandlerOverlay{}, &findings)
			if content == phpCacheMalicious && !findsPath(findings, path) {
				t.Error("legacy stamp hid a payload without file identity")
			}
			if _, ok := scan.merged()[path]; ok {
				t.Error("file without a reliable identity was cached as clean")
			}
		})
	}
}

func TestPHPContentCacheLegacyEntryMissesOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.php")
	mtime := time.Unix(1700000000, 0)
	writePHPFixture(t, path, phpCacheBenign, mtime)
	settlePHPCacheStamps(t, path)
	stateDir := t.TempDir()
	legacy, err := json.Marshal(map[string]map[string]int64{
		path: {"m": mtime.Unix(), "s": int64(len(phpCacheBenign))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "phpcontentcache.json"), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	old := loadPHPContentCache(stateDir)
	if len(old) != 1 {
		t.Fatalf("legacy fixture did not load: %v", old)
	}
	withMockOS(t, phpWriteOnlyOS{path: path})
	miss := newPHPContentScan(&config.Config{}, old, false)
	var findings []alert.Finding
	miss.scanFile(context.Background(), path, phpHandlerOverlay{}, &findings)
	if _, ok := miss.next[path]; ok {
		t.Fatal("legacy entry skipped the required read")
	}
	withMockOS(t, realOS{})
	upgraded := newPHPContentScan(&config.Config{}, loadPHPContentCache(stateDir), false)
	upgraded.scanFile(context.Background(), path, phpHandlerOverlay{}, &findings)
	if _, ok := upgraded.next[path]; !ok {
		t.Fatal("legacy entry was not replaced after a clean read")
	}
	savePHPContentCache(stateDir, upgraded.next)
	withMockOS(t, phpWriteOnlyOS{path: path})
	hit := newPHPContentScan(&config.Config{}, loadPHPContentCache(stateDir), false)
	hit.scanFile(context.Background(), path, phpHandlerOverlay{}, &findings)
	if _, ok := hit.next[path]; !ok {
		t.Fatal("upgraded entry did not skip the next read")
	}
}

func TestPHPContentCacheStampAge(t *testing.T) {
	now := time.Unix(1700000000, 500000000)
	for _, tc := range []struct {
		name  string
		ctime time.Time
		want  bool
	}{
		{"future", now.Add(time.Second), false},
		{"same tick", now, false},
		{"recent", now.Add(-time.Millisecond), false},
		{"boundary", now.Add(-time.Second), false},
		{"stable", now.Add(-time.Second - time.Nanosecond), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stamp := phpFileStamp{Inode: 1, Ctime: tc.ctime.UnixNano()}
			if got := stamp.cacheableAt(now); got != tc.want {
				t.Fatalf("cacheableAt = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPHPContentCacheRejectsRecentStamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.php")
	fresh := true
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == path && fresh {
				fresh = false
				// Change after the scan's start time so scheduler delays
				// cannot accidentally turn this into a stable-file test.
				writePHPFixture(t, path, phpCacheBenign, time.Unix(1700000000, 0))
			}
			return os.Stat(name)
		},
		open: os.Open,
	})
	scan := newPHPContentScan(&config.Config{}, nil, false)
	var findings []alert.Finding
	scan.scanFile(context.Background(), path, phpHandlerOverlay{}, &findings)
	if _, ok := scan.merged()[path]; ok {
		t.Fatal("recent clean read was cached before a same-tick write could change ctime")
	}
	withMockOS(t, realOS{})
	settlePHPCacheStamps(t, path)
	scan.scanFile(context.Background(), path, phpHandlerOverlay{}, &findings)
	if _, ok := scan.next[path]; !ok {
		t.Fatal("stable clean file was not cached on its next read")
	}
}

func TestPHPContentCacheBindsStampToOpenedFile(t *testing.T) {
	for _, cacheHit := range []bool{false, true} {
		name := "miss"
		if cacheHit {
			name = "hit"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "x.php")
			twin := filepath.Join(t.TempDir(), "twin.php")
			content, openedContent := phpCacheMalicious, phpCacheBenign
			if cacheHit {
				content, openedContent = phpCacheBenign, phpCacheMalicious
			}
			mtime := time.Unix(1700000000, 0)
			writePHPFixture(t, path, content, mtime)
			writePHPFixture(t, twin, openedContent, mtime)
			settlePHPCacheStamps(t, path, twin)
			prev := phpContentCache{}
			if cacheHit {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				prev[path] = phpFileStampOf(info)
			}
			withMockOS(t, openRedirectOS{from: path, to: twin})
			scan := newPHPContentScan(&config.Config{}, prev, false)
			var findings []alert.Finding
			scan.scanFile(context.Background(), path, phpHandlerOverlay{}, &findings)
			if cacheHit && !findsPath(findings, path) {
				t.Error("path changed between Stat and Open but its payload was skipped")
			}
			if _, ok := scan.merged()[path]; ok {
				t.Error("clean bytes from another inode validated the path's stamp")
			}
		})
	}
}

type phpAfterReadOS struct {
	realOS
	path    string
	stats   int
	change  func()
	statErr error
}

func (o *phpAfterReadOS) Stat(path string) (os.FileInfo, error) {
	info, err := o.realOS.Stat(path)
	if path == o.path {
		o.stats++
		if o.stats == 2 {
			if o.statErr != nil {
				return nil, o.statErr
			}
			// Return the path snapshot taken before the write. The descriptor
			// must also be checked after reading, not just the pathname.
			if o.change != nil {
				o.change()
			}
		}
	}
	return info, err
}

func TestPHPContentCacheRejectsChangeDuringRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.php")
	mtime := time.Unix(1700000000, 0)
	writePHPFixture(t, path, phpCacheBenign, mtime)
	settlePHPCacheStamps(t, path)
	fs := &phpAfterReadOS{path: path, change: func() {
		swapPreservingMtime(t, path, phpCacheMalicious, mtime)
	}}
	withMockOS(t, fs)
	scan := newPHPContentScan(&config.Config{}, nil, false)
	var findings []alert.Finding
	scan.scanFile(context.Background(), path, phpHandlerOverlay{}, &findings)
	if _, ok := scan.merged()[path]; ok {
		t.Fatal("clean read was cached without checking for concurrent changes")
	}
	if fs.stats != 2 {
		t.Fatalf("expected path revalidation after reading, got %d stats", fs.stats)
	}
	scan.scanFile(context.Background(), path, phpHandlerOverlay{}, &findings)
	if !findsPath(findings, path) {
		t.Fatal("next read did not detect the concurrent payload")
	}
}

func TestPHPContentCacheRejectsFailedRevalidation(t *testing.T) {
	for _, statErr := range []error{os.ErrNotExist, os.ErrPermission} {
		t.Run(statErr.Error(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "x.php")
			writePHPFixture(t, path, phpCacheBenign, time.Unix(1700000000, 0))
			settlePHPCacheStamps(t, path)
			withMockOS(t, &phpAfterReadOS{path: path, statErr: statErr})
			scan := newPHPContentScan(&config.Config{}, nil, false)
			var findings []alert.Finding
			scan.scanFile(context.Background(), path, phpHandlerOverlay{}, &findings)
			if _, ok := scan.merged()[path]; ok {
				t.Fatal("failed revalidation left a reusable clean stamp")
			}
		})
	}
}

func BenchmarkPHPContentCacheRoundTrip(b *testing.B) {
	const count = 200000
	cache := make(phpContentCache, count)
	for i := 0; i < count; i++ {
		path := fmt.Sprintf("/home/account/public_html/wp-content/plugins/plugin/file-%06d.php", i)
		cache[path] = phpFileStamp{Mtime: 1700000000, Size: 16384, Dev: 2049, Inode: uint64(i + 1), Ctime: 1700000000123456789}
	}
	stateDir := b.TempDir()
	savePHPContentCache(stateDir, cache)
	info, err := os.Stat(filepath.Join(stateDir, "phpcontentcache.json"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		savePHPContentCache(stateDir, cache)
		loaded := loadPHPContentCache(stateDir)
		if len(loaded) != count {
			b.Fatalf("cache retained %d of %d files", len(loaded), count)
		}
		for path, stamp := range cache {
			if loaded[path] != stamp {
				b.Fatalf("stamp did not survive persistence: %s", path)
			}
		}
	}
	b.ReportMetric(float64(info.Size())/count, "bytes/file")
}
