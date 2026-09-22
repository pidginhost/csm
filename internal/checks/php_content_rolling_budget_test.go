package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// newRollingAccounts builds one docroot per account under a temp /home tree,
// each holding a single dormant payload outside the fixed suspicious dirs, so
// only rolling coverage can reach it. Returns the temp root and the logical
// /home path of each account's payload, in account order.
func newRollingAccounts(t *testing.T, accounts ...string) (string, map[string]string) {
	t.Helper()
	root := t.TempDir()
	payloads := make(map[string]string, len(accounts))
	for _, account := range accounts {
		dir := filepath.Join(root, "home", account, "public_html", "assets")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "dormant.php"), rollingDormantPHP)
		payloads[account] = "/home/" + account + "/public_html/assets/dormant.php"
	}
	return root, payloads
}

// Rolling coverage sized its window with the per-account file cap and then ran
// it once per account, so a host with hundreds of accounts asked for hundreds
// of windows in one check budget and never finished. The cap is the budget for
// the cycle, shared by the accounts the cycle reaches.
func TestRollingContentSharesOneBudgetAcrossAccounts(t *testing.T) {
	resetPHPContentScanCounts(t)
	root, payloads := newRollingAccounts(t, "aaa", "zzz")
	withMockOS(t, rollingRootOS{root: root})
	useRollingStore(t)

	findings := CheckPHPContent(context.Background(), rollingCfg(1), nil)

	if !findsPath(findings, payloads["aaa"]) {
		t.Fatalf("first account in rolling order was not scanned: %+v", findings)
	}
	if findsPath(findings, payloads["zzz"]) {
		t.Fatalf("second account was scanned although the cycle budget was spent: %+v", findings)
	}
}

// The account walk always restarts at the alphabetically first account, so once
// the budget ran out mid-host the same prefix was rescanned every cycle and the
// tail was never covered. Accounts are ordered by how long ago they last
// completed a traversal, so the cycle after one wraps moves on to the next.
func TestRollingContentAdvancesToNextAccountNextCycle(t *testing.T) {
	resetPHPContentScanCounts(t)
	root, payloads := newRollingAccounts(t, "aaa", "zzz")
	withMockOS(t, rollingRootOS{root: root})
	useRollingStore(t)

	cfg := rollingCfg(1)
	ctx := context.Background()

	first := CheckPHPContent(ctx, cfg, nil)
	if !findsPath(first, payloads["aaa"]) {
		t.Fatalf("cycle 1 did not scan the first account: %+v", first)
	}

	second := CheckPHPContent(ctx, cfg, nil)
	if !findsPath(second, payloads["zzz"]) {
		t.Fatalf("cycle 2 did not advance to the uncovered account: %+v", second)
	}
}

// Rolling coverage stamps clean files outside the fixed suspicious dirs, and
// those stamps are carried forward across cycles now. Enumeration reads every
// directory under the account's docroots, so a file that has since been
// deleted must be dropped rather than kept forever.
func TestRollingContentPrunesDeletedFileFromEnumeratedDir(t *testing.T) {
	resetPHPContentScanCounts(t)
	root, _ := newRollingAccounts(t, "aaa")
	withMockOS(t, rollingRootOS{root: root})
	useRollingStore(t)

	gone := "/home/aaa/public_html/assets/removed.php"
	stateDir := t.TempDir()
	cfg := rollingCfg(10)
	cfg.StatePath = stateDir
	savePHPContentCache(stateDir, phpContentCache{gone: {Mtime: 1, Size: 1}})

	CheckPHPContent(context.Background(), cfg, nil)

	if _, ok := loadPHPContentCache(stateDir)[gone]; ok {
		t.Fatal("stamp for a deleted file in an enumerated directory survived")
	}
}

// Rolling covers one window per cycle, so most of an account's stamps come
// from earlier cycles. They have to survive the cycles that do not revisit
// them, or every window pays the full read cost again.
func TestRollingContentKeepsStampsFromEarlierWindows(t *testing.T) {
	resetPHPContentScanCounts(t)
	root := t.TempDir()
	dir := filepath.Join(root, "home", "aaa", "public_html", "assets")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "a.php"), rollingBenignPHP)
	writeFile(t, filepath.Join(dir, "b.php"), rollingBenignPHP)
	waitForPHPCacheStamp(t, filepath.Join(dir, "a.php"), filepath.Join(dir, "b.php"))
	withMockOS(t, rollingRootOS{root: root})
	useRollingStore(t)

	stateDir := t.TempDir()
	cfg := rollingCfg(1)
	cfg.StatePath = stateDir

	CheckPHPContent(context.Background(), cfg, nil)
	CheckPHPContent(context.Background(), cfg, nil)

	cache := loadPHPContentCache(stateDir)
	for _, name := range []string{"a.php", "b.php"} {
		if _, ok := cache["/home/aaa/public_html/assets/"+name]; !ok {
			t.Fatalf("stamp for %s is missing after two windows: %v", name, cache)
		}
	}
}

func TestRollingContentPrunesWithoutCompletingTraversal(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprint(empty), func(t *testing.T) {
			resetPHPContentScanCounts(t)
			root, _ := newRollingAccounts(t, "aaa")
			dir := filepath.Join(root, "home/aaa/public_html/assets")
			if empty {
				if err := os.Remove(filepath.Join(dir, "dormant.php")); err != nil {
					t.Fatal(err)
				}
			} else {
				writeFile(t, filepath.Join(dir, "z.php"), rollingBenignPHP)
			}
			withMockOS(t, rollingRootOS{root: root})
			useRollingStore(t)
			cfg := rollingCfg(1)
			cfg.StatePath = t.TempDir()
			gone := "/home/aaa/public_html/assets/gone.php"
			savePHPContentCache(cfg.StatePath, phpContentCache{gone: {Mtime: 1, Size: 1}})
			CheckPHPContent(context.Background(), cfg, nil)
			if _, ok := loadPHPContentCache(cfg.StatePath)[gone]; ok {
				t.Fatal("deleted file survived enumeration")
			}
		})
	}
}

func TestRollingContentCursorFailureDoesNotStarveAccounts(t *testing.T) {
	resetPHPContentScanCounts(t)
	root, payloads := newRollingAccounts(t, "aaa", "zzz")
	withMockOS(t, rollingRootOS{root: root})
	db := useRollingStore(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := rollingCfg(1)
	first := CheckPHPContent(context.Background(), cfg, nil)
	second := CheckPHPContent(context.Background(), cfg, nil)
	if !findsPath(first, payloads["aaa"]) {
		t.Fatal("first account was not scanned")
	}
	if !findsPath(second, payloads["zzz"]) {
		t.Fatal("failed cursor write starved second account")
	}
	if findsPath(second, payloads["aaa"]) {
		t.Fatal("shared file budget was exceeded")
	}
}

func TestRollingContentPeriodicRefreshInvalidatesUnvisitedStamps(t *testing.T) {
	resetPHPContentScanCounts(t)
	root, payloads := newRollingAccounts(t, "aaa")
	withMockOS(t, rollingRootOS{root: root})
	useRollingStore(t)
	cfg := rollingCfg(1)
	cfg.StatePath = t.TempDir()
	path := filepath.Join(root, payloads["aaa"])
	mtime := time.Unix(1700000000, 0)
	writePHPFixture(t, path, rollingBenignPHP, mtime)
	waitForPHPCacheStamp(t, path)
	CheckPHPContent(context.Background(), cfg, nil)
	if _, ok := loadPHPContentCache(cfg.StatePath)[payloads["aaa"]]; !ok {
		t.Fatal("rolling scan did not cache the clean seed")
	}
	payload := rollingDormantPHP + strings.Repeat(" ", len(rollingBenignPHP)-len(rollingDormantPHP))
	writePHPFixture(t, path, payload, mtime)
	waitForPHPCacheStamp(t, path)
	// Model unchanged metadata so only the periodic refresh can invalidate
	// this entry, even on filesystems that distinguish the two writes.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	savePHPContentCache(cfg.StatePath, phpContentCache{payloads["aaa"]: phpFileStampOf(info)})
	for range 5 {
		if findings := CheckPHPContent(context.Background(), cfg, nil); findsPath(findings, payloads["aaa"]) {
			t.Fatal("cached rolling-only file was read before the periodic refresh")
		}
	}
	if _, ok := loadPHPContentCache(cfg.StatePath)[payloads["aaa"]]; ok {
		t.Fatal("periodic refresh retained an unvisited stamp")
	}
	findings := CheckPHPContent(context.Background(), cfg, nil)
	if !findsPath(findings, payloads["aaa"]) {
		t.Fatal("rolling-only payload evaded periodic cache refresh")
	}
}

func TestRollingContentInvalidatesUnstatableCandidate(t *testing.T) {
	useRollingStore(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "a.php")
	writeFile(t, path, rollingBenignPHP)
	withMockOS(t, &mockOS{
		readDir: os.ReadDir,
		stat: func(name string) (os.FileInfo, error) {
			if name == path {
				return nil, os.ErrPermission
			}
			return os.Stat(name)
		},
	})
	scan := newPHPContentScan(rollingCfg(1), phpContentCache{path: {Mtime: 1, Size: 1}}, false)
	var findings []alert.Finding
	_, used := rollingContentCoverage(context.Background(), scan.cfg, scan, "aaa", []string{dir}, 1, &findings)
	if used != 0 {
		t.Fatalf("unstatable file charged as a read: %d", used)
	}
	if _, ok := scan.merged()[path]; ok {
		t.Fatal("unstatable candidate kept its clean stamp")
	}
}

func TestRollingContentPruningRetainsUnenumeratedExistingFiles(t *testing.T) {
	useRollingStore(t)
	dir := t.TempDir()
	remapped := filepath.Join(dir, "payload.inc")
	unreadable := filepath.Join(dir, "blocked", "a.php")
	gone := filepath.Join(dir, "gone.php")
	writeFile(t, remapped, rollingBenignPHP)
	withMockOS(t, &mockOS{
		readDir: os.ReadDir,
		stat: func(name string) (os.FileInfo, error) {
			if name == unreadable {
				return nil, os.ErrPermission
			}
			return os.Stat(name)
		},
	})
	prev := phpContentCache{}
	for _, path := range []string{remapped, unreadable, gone} {
		prev[path] = phpFileStamp{Mtime: 1, Size: 1}
	}
	scan := newPHPContentScan(rollingCfg(1), prev, false)
	var findings []alert.Finding
	rollingContentCoverage(context.Background(), scan.cfg, scan, "aaa", []string{dir}, 1, &findings)
	cache := scan.merged()
	for _, path := range []string{remapped, unreadable} {
		if _, ok := cache[path]; !ok {
			t.Fatalf("enumeration incorrectly treated %s as deleted", path)
		}
	}
	if _, ok := cache[gone]; ok {
		t.Fatal("deleted file survived an empty window")
	}
}

func TestRollingContentCursorFailureStillAdvancesWithinAccount(t *testing.T) {
	resetPHPContentScanCounts(t)
	root, payloads := newRollingAccounts(t, "aaa", "zzz")
	writeFile(t, filepath.Join(root, "home/aaa/public_html/assets/a.php"), rollingBenignPHP)
	withMockOS(t, rollingRootOS{root: root})
	db := useRollingStore(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := rollingCfg(1)
	for cycle := 1; cycle <= 4; cycle++ {
		findings := CheckPHPContent(context.Background(), cfg, nil)
		wantAAA := cycle == 2
		wantZZZ := cycle == 4
		if findsPath(findings, payloads["aaa"]) != wantAAA || findsPath(findings, payloads["zzz"]) != wantZZZ {
			t.Fatalf("cycle %d lost cursor progress or exceeded its budget: %v", cycle, findings)
		}
	}
}

func TestPHPContentCursorFallbackRecoveryAndRetention(t *testing.T) {
	db := useRollingStore(t)
	old := store.ScanCursorRecord{Account: "aaa", Check: rollingScanCheck, LastPath: "a.php"}
	if err := db.PutScanCursor(old); err != nil {
		t.Fatal(err)
	}
	pending := old
	pending.LastPath = "b.php"
	c := phpContentCursors{db: db, pending: map[string]store.ScanCursorRecord{"aaa": pending}}
	if got, err := c.load(db, "aaa"); err != nil || got.LastPath != pending.LastPath {
		t.Fatalf("stale persisted cursor replaced unpersisted progress: %v %v", got, err)
	}
	if err := c.save(db, pending); err != nil {
		t.Fatal(err)
	}
	if len(c.pending) != 0 {
		t.Fatal("successful persistence retained a fallback")
	}
	if got, _, err := db.GetScanCursor("aaa", rollingScanCheck); err != nil || got.LastPath != pending.LastPath {
		t.Fatalf("recovered storage did not persist progress: %v %v", got, err)
	}
	// Account deletion must discard unpersisted state even if the store is
	// still unavailable; recreating the account must start from disk again.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.save(db, pending); err == nil {
		t.Fatal("closed database accepted a cursor")
	}
	c.retain(db, nil)
	if got, _ := c.load(db, "aaa"); got.LastPath != "" {
		t.Fatal("removed account retained stale in-memory progress")
	}
}
