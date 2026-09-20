package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
