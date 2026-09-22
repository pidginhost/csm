package checks

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The php_content deep scan reads and parses every .php file under every
// account's wp-content tree on every cycle. On large multi-tenant hosts that
// is hundreds of thousands of files and pushes the check against its timeout.
// A per-file stamp cache lets unchanged, previously-clean files skip the
// read+parse. These tests pin the cache's exact semantics and the safety nets
// that bound it.

const phpCacheBenign = "<?php echo 1; // benign filler kept long enough!!"
const phpCacheMalicious = "<?php system($_POST['c']); // webshell padding go"

func init() {
	// Both fixtures must be the same byte length so a content swap can hold
	// size constant and isolate the other stamp fields.
	if len(phpCacheBenign) != len(phpCacheMalicious) {
		panic("php cache test fixtures must be equal length")
	}
}

func writePHPFixture(t *testing.T, path, content string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

// openRedirectOS serves the real filesystem except that opening one path
// yields another file's content. Stat still reports the real file, so a scan
// sees an unchanged stamp while any read it makes returns the other bytes.
type openRedirectOS struct {
	realOS
	from, to string
}

func (o openRedirectOS) Open(name string) (*os.File, error) {
	if name == o.from {
		return os.Open(o.to)
	}
	return o.realOS.Open(name)
}

func TestPHPContentCacheSkipsUnchangedCleanFile(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	path := filepath.Join(dir, "x.php")
	writePHPFixture(t, path, phpCacheBenign, time.Unix(1_700_000_000, 0))
	waitForPHPCacheStamp(t, path)
	s1 := newPHPContentScan(cfg, nil, false)
	var f1 []alert.Finding
	s1.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f1)
	if len(f1) != 0 {
		t.Fatalf("benign file should produce no finding, got %d", len(f1))
	}

	if _, ok := s1.next[path]; !ok {
		t.Fatal("clean seed was not cached")
	}
	// The descriptor has the same identity but rejects reads. Retaining the
	// stamp proves the hit skipped analysis; a forced read cannot cache it.
	withMockOS(t, phpWriteOnlyOS{path: path})

	want := s1.next[path]
	s2 := newPHPContentScan(cfg, s1.next, false)
	var f2 []alert.Finding
	s2.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f2)
	if stamp, ok := s2.next[path]; len(f2) != 0 || !ok || stamp != want {
		t.Fatalf("unchanged clean stamp was not reused: cache=%v findings=%v", s2.next, f2)
	}
	s3 := newPHPContentScan(cfg, s1.next, true)
	var f3 []alert.Finding
	s3.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f3)
	if _, ok := s3.next[path]; ok {
		t.Fatal("forced read unexpectedly retained an unreadable file's stamp")
	}
}

// Anyone who can write a file can also set its mtime back, and a same-size
// swap then matched the old mtime+size stamp and skipped analysis until the
// next forced rescan. The inode change time cannot be set from user space,
// so the stamp includes it.
func TestPHPContentCacheDetectsSwapThatRestoresMtime(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	path := filepath.Join(dir, "x.php")
	mtime := time.Unix(1_700_000_000, 0)

	writePHPFixture(t, path, phpCacheBenign, mtime)
	waitForPHPCacheStamp(t, path)
	s1 := newPHPContentScan(cfg, nil, false)
	var f1 []alert.Finding
	s1.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f1)

	swapPreservingMtime(t, path, phpCacheMalicious, mtime)
	s2 := newPHPContentScan(cfg, s1.next, false)
	var f2 []alert.Finding
	s2.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f2)
	if len(f2) == 0 {
		t.Fatal("same-size swap with the mtime restored was skipped as unchanged")
	}
}

// swapPreservingMtime rewrites path in place and restores its mtime, retrying
// until the change time has moved: Linux stamps it from a coarse clock, so a
// rewrite in the same tick as the previous change can carry the same value.
func swapPreservingMtime(t *testing.T, path, content string, mtime time.Time) {
	t.Helper()
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	was, ok := selfWriteIdentityFromFileInfo(before)
	if !ok {
		t.Fatal("platform exposes no inode change time")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		writePHPFixture(t, path, content, mtime)
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if now, _ := selfWriteIdentityFromFileInfo(after); now != was {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("inode change time never moved")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPHPContentCacheReanalyzesOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	path := filepath.Join(dir, "x.php")
	mtime := time.Unix(1_700_000_000, 0)

	writePHPFixture(t, path, phpCacheBenign, mtime)
	waitForPHPCacheStamp(t, path)
	s1 := newPHPContentScan(cfg, nil, false)
	var f1 []alert.Finding
	s1.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f1)

	// Same size, newer mtime -> cache miss -> must re-analyze and detect.
	writePHPFixture(t, path, phpCacheMalicious, mtime.Add(100*time.Second))
	s2 := newPHPContentScan(cfg, s1.next, false)
	var f2 []alert.Finding
	s2.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f2)
	if len(f2) == 0 {
		t.Fatal("mtime change must trigger re-analysis and detect the webshell")
	}
}

func TestPHPContentCacheReanalyzesOnSizeChange(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	path := filepath.Join(dir, "x.php")
	mtime := time.Unix(1_700_000_000, 0)

	writePHPFixture(t, path, phpCacheBenign, mtime)
	waitForPHPCacheStamp(t, path)
	s1 := newPHPContentScan(cfg, nil, false)
	var f1 []alert.Finding
	s1.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f1)

	// Different size, same mtime -> cache miss -> must re-analyze.
	writePHPFixture(t, path, phpCacheMalicious+" extra bytes change size", mtime)
	s2 := newPHPContentScan(cfg, s1.next, false)
	var f2 []alert.Finding
	s2.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f2)
	if len(f2) == 0 {
		t.Fatal("size change must trigger re-analysis and detect the webshell")
	}
}

func TestPHPContentCacheForceFullRescanIgnoresCache(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	path := filepath.Join(dir, "x.php")
	mtime := time.Unix(1_700_000_000, 0)

	writePHPFixture(t, path, phpCacheBenign, mtime)
	waitForPHPCacheStamp(t, path)
	s1 := newPHPContentScan(cfg, nil, false)
	var f1 []alert.Finding
	s1.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f1)

	// Model a filesystem returning a stale, matching stamp. A forced scan
	// must read even when every cache field matches the current metadata.
	writePHPFixture(t, path, phpCacheMalicious, mtime)
	waitForPHPCacheStamp(t, path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	s1.next[path] = phpFileStampOf(info)
	s2 := newPHPContentScan(cfg, s1.next, true)
	var f2 []alert.Finding
	s2.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f2)
	if len(f2) == 0 {
		t.Fatal("forced full rescan must ignore cache and detect the webshell")
	}
}

func TestPHPContentForceFullHostCadenceIgnoresAccountScans(t *testing.T) {
	resetPHPContentScanCounts(t)

	for i := 0; i < 5; i++ {
		if phpContentForceFull(context.Background()) {
			t.Fatalf("host scan %d should not force a full rescan", i+1)
		}
	}

	accountCtx := ContextWithAccountScope(context.Background(), "alice")
	for i := 0; i < 20; i++ {
		_ = phpContentForceFull(accountCtx)
	}

	if !phpContentForceFull(context.Background()) {
		t.Fatal("sixth host-wide scan must force a full rescan even after account scans")
	}
}

func TestPHPContentCacheDirtyFileAlwaysSurfaces(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	path := filepath.Join(dir, "x.php")
	mtime := time.Unix(1_700_000_000, 0)

	writePHPFixture(t, path, phpCacheMalicious, mtime)
	s1 := newPHPContentScan(cfg, nil, false)
	var f1 []alert.Finding
	s1.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f1)
	if len(f1) == 0 {
		t.Fatal("malicious file must be detected on first scan")
	}
	if _, ok := s1.next[path]; ok {
		t.Fatal("a file with a finding must not be cached as clean")
	}

	// Unchanged malicious file on a later cycle must still surface, because
	// findings drive the alert pipeline every cycle; only clean files skip.
	s2 := newPHPContentScan(cfg, s1.next, false)
	var f2 []alert.Finding
	s2.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f2)
	if len(f2) == 0 {
		t.Fatal("unchanged malicious file must still surface on subsequent scans")
	}
}

func TestPHPContentCacheDoesNotCarryUnreadableCacheHit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.php")
	mtime := time.Unix(1_700_000_000, 0)
	writePHPFixture(t, path, phpCacheBenign, mtime)
	waitForPHPCacheStamp(t, path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stamp := phpFileStampOf(info)

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == dir {
				return []os.DirEntry{testDirEntry{name: "x.php", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == path {
				return info, nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == path {
				return nil, os.ErrPermission
			}
			return nil, os.ErrNotExist
		},
	})

	s := newPHPContentScan(&config.Config{}, phpContentCache{path: stamp}, false)
	var findings []alert.Finding
	s.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &findings)
	if _, ok := s.next[path]; ok {
		t.Fatal("unreadable cache hit must not be carried forward as clean")
	}
}

func TestPHPContentCacheRecordsEmptyReadableFile(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	path := filepath.Join(dir, "empty.php")
	mtime := time.Unix(1_700_000_000, 0)

	writePHPFixture(t, path, "", mtime)
	waitForPHPCacheStamp(t, path)
	s := newPHPContentScan(cfg, nil, false)
	var findings []alert.Finding
	s.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &findings)
	if len(findings) != 0 {
		t.Fatalf("empty readable file should produce no finding, got %d", len(findings))
	}
	if _, ok := s.next[path]; !ok {
		t.Fatal("empty readable file should be recorded in the clean cache")
	}
}

func TestPHPContentCachePrunesDeletedFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	path := filepath.Join(dir, "x.php")
	mtime := time.Unix(1_700_000_000, 0)

	writePHPFixture(t, path, phpCacheBenign, mtime)
	waitForPHPCacheStamp(t, path)
	s1 := newPHPContentScan(cfg, nil, false)
	var f1 []alert.Finding
	s1.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f1)
	if _, ok := s1.next[path]; !ok {
		t.Fatal("clean file should be recorded in cache")
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	s2 := newPHPContentScan(cfg, s1.next, false)
	var f2 []alert.Finding
	s2.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f2)
	if _, ok := s2.next[path]; ok {
		t.Fatal("deleted file must be pruned from the next cache")
	}
}

func TestPHPContentCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := phpContentCache{
		"/home/a/public_html/wp-content/plugins/a.php": {Mtime: 11, Size: 22, Dev: 2049, Inode: 1<<63 + 7, Ctime: 1700000000123456789},
		"/home/b/public_html/wp-content/themes/b.php":  {Mtime: 33, Size: 44, Dev: 0, Inode: 99, Ctime: 1700000000987654321},
	}
	savePHPContentCache(dir, c)
	got := loadPHPContentCache(dir)
	if len(got) != len(c) {
		t.Fatalf("round-trip size mismatch: got %d want %d", len(got), len(c))
	}
	for k, v := range c {
		if got[k] != v {
			t.Errorf("entry %s: got %+v want %+v", k, got[k], v)
		}
	}
}

func TestPHPContentCacheEmptyStateDirIsNoop(t *testing.T) {
	// An unset state path must not read or write a cache file in the process
	// working directory. Several callers invoke CheckPHPContent with a
	// zero-value config (no StatePath), and a stray cwd file would otherwise be
	// loaded as if it were trusted state.
	savePHPContentCache("", phpContentCache{"/x.php": {Mtime: 1, Size: 2}})
	if _, err := os.Stat("phpcontentcache.json"); err == nil {
		_ = os.Remove("phpcontentcache.json")
		t.Fatal("empty state dir must not write a cache file to the working directory")
	}
	if got := loadPHPContentCache(""); len(got) != 0 {
		t.Fatalf("empty state dir must load no cache, got %d entries", len(got))
	}
}

func TestLoadPHPContentCacheMissingFile(t *testing.T) {
	got := loadPHPContentCache(t.TempDir())
	if got == nil {
		t.Fatal("missing cache file should yield an empty, non-nil map")
	}
	if len(got) != 0 {
		t.Fatalf("missing cache file should be empty, got %d", len(got))
	}
}

func resetPHPContentScanCounts(t *testing.T) {
	t.Helper()
	oldHost := atomic.LoadInt32(&phpContentHostScanCount)
	oldAccount := atomic.LoadInt32(&phpContentAccountScanCount)
	atomic.StoreInt32(&phpContentHostScanCount, 0)
	atomic.StoreInt32(&phpContentAccountScanCount, 0)
	t.Cleanup(func() {
		atomic.StoreInt32(&phpContentHostScanCount, oldHost)
		atomic.StoreInt32(&phpContentAccountScanCount, oldAccount)
	})
}
