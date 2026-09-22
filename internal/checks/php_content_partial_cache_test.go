package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// cancelOnReadDirOS cancels a scan the first time it reads a directory under
// trigger, so a host-wide walk can be cut short at a known account boundary.
type cancelOnReadDirOS struct {
	realOS
	trigger string
	cancel  context.CancelFunc
}

func (c cancelOnReadDirOS) ReadDir(name string) ([]os.DirEntry, error) {
	if strings.HasPrefix(name, c.trigger) {
		c.cancel()
	}
	return os.ReadDir(name)
}

func seedPHPAccount(t *testing.T, homeRoot, account string, mtime time.Time) string {
	t.Helper()
	dir := filepath.Join(homeRoot, account, "public_html", "wp-content", "plugins")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	path := filepath.Join(dir, "p.php")
	writePHPFixture(t, path, phpCacheBenign, mtime)
	return path
}

// The php_content check on a busy host runs out of budget before it reaches the
// last account, so it never persisted its clean-file cache at all: the next
// cycle re-read every file and ran out of budget again. A run cut short must
// keep the stamps it confirmed this cycle and carry forward the prior stamps
// for directories it never reached.
func TestCheckPHPContentPersistsCacheWhenCutShort(t *testing.T) {
	resetPHPContentScanCounts(t)
	homeRoot := t.TempDir()
	stateDir := t.TempDir()
	cfg := &config.Config{StatePath: stateDir}
	mtime := time.Unix(1_700_000_000, 0)

	first := seedPHPAccount(t, homeRoot, "aaa", mtime)
	last := seedPHPAccount(t, homeRoot, "zzz", mtime)
	waitForPHPCacheStamp(t, first, last)

	prevRoots := accountHomeRoots
	t.Cleanup(func() { accountHomeRoots = prevRoots })
	accountHomeRoots = func() []string { return []string{homeRoot} }

	savePHPContentCache(stateDir, phpContentCache{
		last: {Mtime: mtime.Unix(), Size: int64(len(phpCacheBenign))},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	withMockOS(t, cancelOnReadDirOS{trigger: filepath.Join(homeRoot, "zzz"), cancel: cancel})

	CheckPHPContent(ctx, cfg, nil)

	got := loadPHPContentCache(stateDir)
	if _, ok := got[first]; !ok {
		t.Fatalf("stamp for the scanned file was not persisted: %v", got)
	}
	if _, ok := got[last]; !ok {
		t.Fatalf("prior stamp for the unreached account was dropped: %v", got)
	}
}

// A completed walk still prunes: a file that disappeared from a directory the
// run did read must not survive in the cache, or a path could be recreated
// later with the same mtime and size and skip analysis.
func TestCheckPHPContentPrunesDeletedFileFromVisitedDir(t *testing.T) {
	resetPHPContentScanCounts(t)
	homeRoot := t.TempDir()
	stateDir := t.TempDir()
	cfg := &config.Config{StatePath: stateDir}
	mtime := time.Unix(1_700_000_000, 0)

	kept := seedPHPAccount(t, homeRoot, "aaa", mtime)
	waitForPHPCacheStamp(t, kept)
	gone := filepath.Join(filepath.Dir(kept), "deleted.php")

	prevRoots := accountHomeRoots
	t.Cleanup(func() { accountHomeRoots = prevRoots })
	accountHomeRoots = func() []string { return []string{homeRoot} }

	savePHPContentCache(stateDir, phpContentCache{
		kept: {Mtime: mtime.Unix(), Size: int64(len(phpCacheBenign))},
		gone: {Mtime: mtime.Unix(), Size: int64(len(phpCacheBenign))},
	})

	CheckPHPContent(context.Background(), cfg, nil)

	got := loadPHPContentCache(stateDir)
	if _, ok := got[kept]; !ok {
		t.Fatalf("stamp for the surviving file was dropped: %v", got)
	}
	if _, ok := got[gone]; ok {
		t.Fatalf("stamp for a deleted file in a scanned directory survived: %v", got)
	}
}

// An attempted file must invalidate its old clean stamp even if cancellation
// prevents scanDir from finishing the directory, or rolling reads it alone.
type interruptedPHPReadOS struct {
	realOS
	path       string
	cancel     context.CancelFunc
	unreadable bool
}

func (o interruptedPHPReadOS) Open(path string) (*os.File, error) {
	if path == o.path {
		o.cancel()
		if o.unreadable {
			return nil, os.ErrPermission
		}
	}
	return os.Open(path)
}

func TestPHPContentPartialCacheInvalidatesAttemptedFile(t *testing.T) {
	for _, unreadable := range []bool{false, true} {
		t.Run(fmt.Sprint(unreadable), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "a.php")
			mtime := time.Unix(1700000000, 0)
			writePHPFixture(t, path, rollingDormantPHP, mtime)
			writePHPFixture(t, filepath.Join(dir, "z.php"), phpCacheBenign, mtime)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			withMockOS(t, interruptedPHPReadOS{path: path, cancel: cancel, unreadable: unreadable})
			stamp := phpFileStamp{Mtime: mtime.Unix() - 1, Size: 1}
			if unreadable {
				// The file's own stamp, so the scan takes the cache-hit path
				// and meets the unreadable file there.
				waitForPHPCacheStamp(t, path)
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				stamp = phpFileStampOf(info)
			}
			scan := newPHPContentScan(&config.Config{}, phpContentCache{path: stamp}, false)
			var findings []alert.Finding
			scan.scanDir(ctx, dir, 4, phpHandlerOverlay{}, &findings)
			if !unreadable && !findsPath(findings, path) {
				t.Fatal("payload was not detected")
			}
			if _, ok := scan.merged()[path]; ok {
				t.Fatal("attempted file retained a stale clean stamp")
			}
		})
	}
}

func TestPHPContentCacheInvalidatesEarlierReadInSameRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.php")
	writeFile(t, path, phpCacheBenign)
	waitForPHPCacheStamp(t, path)
	scan := newPHPContentScan(&config.Config{}, nil, false)
	var findings []alert.Finding
	scan.scanFile(context.Background(), path, phpHandlerOverlay{}, &findings)
	if _, ok := scan.next[path]; !ok {
		t.Fatal("clean file was not cached")
	}
	writeFile(t, path, rollingDormantPHP)
	scan.scanFile(context.Background(), path, phpHandlerOverlay{}, &findings)
	if !findsPath(findings, path) {
		t.Fatal("payload was not detected")
	}
	if _, ok := scan.merged()[path]; ok {
		t.Fatal("finding retained this run's earlier clean stamp")
	}
}

type delayedPHPReadOS struct {
	realOS
	path    string
	entered chan struct{}
	release chan struct{}
	blocked atomic.Bool
}

func (o *delayedPHPReadOS) Open(path string) (*os.File, error) {
	if path == o.path && o.blocked.CompareAndSwap(false, true) {
		close(o.entered)
		<-o.release
	}
	return os.Open(path)
}

func TestCheckPHPContentLateCanceledRunCannotReplaceNewerCache(t *testing.T) {
	resetPHPContentScanCounts(t)
	homeRoot := t.TempDir()
	stateDir := t.TempDir()
	cfg := &config.Config{StatePath: stateDir}
	mtime := time.Unix(1700000000, 0)
	path := seedPHPAccount(t, homeRoot, "aaa", mtime)
	writePHPFixture(t, path, rollingBenignPHP, mtime)
	slow := filepath.Join(filepath.Dir(path), "z.php")
	writePHPFixture(t, slow, rollingBenignPHP, mtime)
	waitForPHPCacheStamp(t, path, slow)
	previousRoots := accountHomeRoots
	accountHomeRoots = func() []string { return []string{homeRoot} }
	t.Cleanup(func() { accountHomeRoots = previousRoots })
	fs := &delayedPHPReadOS{path: slow, entered: make(chan struct{}), release: make(chan struct{})}
	withMockOS(t, fs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	release := sync.OnceFunc(func() { close(fs.release) })
	defer func() { release(); <-done }()
	go func() {
		defer close(done)
		CheckPHPContent(ctx, cfg, nil)
	}()
	<-fs.entered
	cancel()
	// A replacement run detects a change after the old run read the clean
	// version, while the old run is still blocked in an unrelated file read.
	payload := rollingDormantPHP + strings.Repeat(" ", len(rollingBenignPHP)-len(rollingDormantPHP))
	writePHPFixture(t, path, payload, mtime.Add(time.Second))
	if findings := CheckPHPContent(context.Background(), cfg, nil); !findsPath(findings, path) {
		t.Fatal("replacement run did not detect the changed file")
	}
	if _, ok := loadPHPContentCache(stateDir)[path]; ok {
		t.Fatal("replacement run cached the payload")
	}
	release()
	<-done
	if _, ok := loadPHPContentCache(stateDir)[path]; ok {
		t.Fatal("late canceled run restored an obsolete clean stamp")
	}
}
