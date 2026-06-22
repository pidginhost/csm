package checks

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// rollingRootOS maps every absolute path under /home onto a real temp tree so
// CheckPHPContent (which hardcodes /home) reads real files. Content analysis
// goes through osFS.Open and needs a real *os.File, so a function-field mock is
// not enough -- this delegates to the real filesystem with a path prefix.
type rollingRootOS struct {
	root string
}

func (r rollingRootOS) translate(name string) string {
	if name == "/home" || strings.HasPrefix(name, "/home/") {
		return filepath.Join(r.root, name)
	}
	return name
}

func (r rollingRootOS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(r.translate(name))
}

func (r rollingRootOS) ReadDir(name string) ([]os.DirEntry, error) {
	return os.ReadDir(r.translate(name))
}

func (r rollingRootOS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(r.translate(name))
}

func (r rollingRootOS) Lstat(name string) (os.FileInfo, error) {
	return os.Lstat(r.translate(name))
}

func (r rollingRootOS) Readlink(name string) (string, error) {
	return os.Readlink(r.translate(name))
}

func (r rollingRootOS) Open(name string) (*os.File, error) {
	return os.Open(r.translate(name))
}

func (r rollingRootOS) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(r.translate(name), data, perm)
}

func (r rollingRootOS) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(r.translate(path), perm)
}

func (r rollingRootOS) Remove(name string) error {
	return os.Remove(r.translate(name))
}

func (r rollingRootOS) Glob(pattern string) ([]string, error) {
	matches, err := filepath.Glob(r.translate(pattern))
	if err != nil {
		return nil, err
	}
	// Strip the temp prefix so callers see /home/... paths.
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if rel, ok := strings.CutPrefix(m, r.root); ok {
			out = append(out, rel)
		} else {
			out = append(out, m)
		}
	}
	return out, nil
}

const rollingBenignPHP = "<?php echo 'hello world from a clean file'; ?>\n"
const rollingDormantPHP = "<?php eval(base64_decode($_POST['x'])); ?>\n"

// rollingFixture builds a single-account docroot under a temp /home tree and a
// fresh bbolt store so the per-account cursor persists between cycles. It
// returns the account name and the absolute (translated, real-FS) path of the
// dormant FOPO file so callers can assert on it.
type rollingFixture struct {
	account string
	dormant string // /home/... logical path of the dormant FOPO file
	root    string // temp /home root
}

func newRollingFixture(t *testing.T) rollingFixture {
	t.Helper()
	root := t.TempDir()
	account := "example-acct"
	home := filepath.Join(root, "home", account)
	docRoot := filepath.Join(home, "public_html")

	// Files inside a fixed suspicious dir (always scanned, regardless of
	// rolling). One clean, so it never produces a finding.
	susDir := filepath.Join(docRoot, "wp-content", "plugins")
	if err := os.MkdirAll(susDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(susDir, "akismet.php"), rollingBenignPHP)

	// A CUSTOM dir OUTSIDE the suspicious dirs. Rolling is the only path that
	// reaches it. Names are path-sorted so the dormant FOPO file sorts LAST and
	// sits beyond `cap` in cycle 1.
	custom := filepath.Join(docRoot, "assets", "lib")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		t.Fatal(err)
	}
	// a00.php .. a04.php are clean; z-dormant.php is the FOPO payload (sorts last).
	for i := 0; i < 5; i++ {
		writeFile(t, filepath.Join(custom, "a0"+strconv.Itoa(i)+".php"), rollingBenignPHP)
	}
	dormant := filepath.Join(custom, "z-dormant.php")
	writeFile(t, dormant, rollingDormantPHP)

	return rollingFixture{
		account: account,
		dormant: "/home/" + account + "/public_html/assets/lib/z-dormant.php",
		root:    root,
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// useRollingStore opens a temp bbolt store and installs it as the global store
// for the duration of the test.
func useRollingStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})
	return db
}

func findsPath(findings []alert.Finding, path string) bool {
	for _, f := range findings {
		if f.FilePath == path {
			return true
		}
	}
	return false
}

func rollingCfg(cap int) *config.Config {
	cfg := &config.Config{}
	cfg.Thresholds.RollingCoverage = true
	cfg.Thresholds.AccountScanMaxFiles = cap
	return cfg
}

// Case 1: eventual coverage. With rolling on and a small cap, the dormant FOPO
// file beyond the cap in sorted order is NOT found on cycle 1 but IS found by
// the expected cycle, and the cursor advances each cycle.
func TestRollingContentEventualCoverage(t *testing.T) {
	resetPHPContentScanCounts(t)
	fx := newRollingFixture(t)
	withMockOS(t, rollingRootOS{root: fx.root})
	db := useRollingStore(t)

	cap := 2
	cfg := rollingCfg(cap)
	ctx := context.Background()

	// 6 custom files sorted: a00,a01,a02,a03,a04,z-dormant. With cap=2 the
	// dormant file (index 5) is reached on cycle 3 (covers 0-1, 2-3, 4-5).
	cycle1 := CheckPHPContent(ctx, cfg, nil)
	if findsPath(cycle1, fx.dormant) {
		t.Fatal("cycle 1: dormant file must NOT be reached yet (beyond cap)")
	}
	cur1, ok1, _ := db.GetScanCursor(fx.account, "php_content")
	if !ok1 || cur1.LastPath == "" {
		t.Fatal("cycle 1: cursor must advance")
	}

	cycle2 := CheckPHPContent(ctx, cfg, nil)
	if findsPath(cycle2, fx.dormant) {
		t.Fatal("cycle 2: dormant file still beyond reach")
	}
	cur2, _, _ := db.GetScanCursor(fx.account, "php_content")
	if cur2.LastPath == cur1.LastPath {
		t.Fatalf("cycle 2: cursor must advance past %q", cur1.LastPath)
	}

	cycle3 := CheckPHPContent(ctx, cfg, nil)
	if !findsPath(cycle3, fx.dormant) {
		t.Fatal("cycle 3: dormant FOPO file MUST be content-scanned and found")
	}
	cur3, _, _ := db.GetScanCursor(fx.account, "php_content")
	if cur3.LastPath == cur2.LastPath {
		t.Fatalf("cycle 3: cursor must advance past %q", cur2.LastPath)
	}
}

// Case 2: rolling off -> the dormant out-of-suspicious-dir file is NEVER found.
func TestRollingContentDisabledNeverReachesDormant(t *testing.T) {
	resetPHPContentScanCounts(t)
	fx := newRollingFixture(t)
	withMockOS(t, rollingRootOS{root: fx.root})
	db := useRollingStore(t)

	cfg := rollingCfg(2)
	cfg.Thresholds.RollingCoverage = false
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		got := CheckPHPContent(ctx, cfg, nil)
		if findsPath(got, fx.dormant) {
			t.Fatalf("cycle %d: rolling off must never reach the dormant file", i+1)
		}
	}
	if _, ok, _ := db.GetScanCursor(fx.account, "php_content"); ok {
		t.Fatal("rolling off must not write a cursor")
	}
}

// Case 3: account-scope run -> rolling does NOT run; cursor untouched.
func TestRollingContentSkippedForAccountScope(t *testing.T) {
	resetPHPContentScanCounts(t)
	fx := newRollingFixture(t)
	withMockOS(t, rollingRootOS{root: fx.root})
	db := useRollingStore(t)

	cfg := rollingCfg(2)
	ctx := ContextWithAccountScope(context.Background(), fx.account)

	got := CheckPHPContent(ctx, cfg, nil)
	if findsPath(got, fx.dormant) {
		t.Fatal("account-scope run must not sweep the dormant file via rolling")
	}
	if _, ok, _ := db.GetScanCursor(fx.account, "php_content"); ok {
		t.Fatal("account-scope run must not advance the rolling cursor")
	}
}

// Case 4: forced content -> rolling does NOT run; cursor untouched. A forced
// content scan already reads every file, so rolling is redundant.
func TestRollingContentSkippedForForcedContent(t *testing.T) {
	resetPHPContentScanCounts(t)
	fx := newRollingFixture(t)
	withMockOS(t, rollingRootOS{root: fx.root})
	db := useRollingStore(t)

	cfg := rollingCfg(2)
	opts := DefaultAccountScanOptions(cfg)
	opts.ForceContent = true
	ctx := ContextWithScanOptions(context.Background(), opts)

	_ = CheckPHPContent(ctx, cfg, nil)
	if _, ok, _ := db.GetScanCursor(fx.account, "php_content"); ok {
		t.Fatal("forced content run must not advance the rolling cursor")
	}
}

// Case 5: cancellation -> cursor NOT advanced (a canceled run leaves the prior
// cursor). Drive one clean cycle to seed a cursor, then cancel partway through
// the next and assert the cursor is unchanged.
func TestRollingContentCancellationPreservesCursor(t *testing.T) {
	resetPHPContentScanCounts(t)
	fx := newRollingFixture(t)
	withMockOS(t, rollingRootOS{root: fx.root})
	db := useRollingStore(t)

	cfg := rollingCfg(2)

	// Seed: one complete cycle advances the cursor.
	_ = CheckPHPContent(context.Background(), cfg, nil)
	seeded, ok, _ := db.GetScanCursor(fx.account, "php_content")
	if !ok {
		t.Fatal("seed cycle must write a cursor")
	}

	// Canceled context: rolling must not persist a new cursor.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = CheckPHPContent(ctx, cfg, nil)

	after, ok2, _ := db.GetScanCursor(fx.account, "php_content")
	if !ok2 {
		t.Fatal("cursor disappeared after canceled run")
	}
	if after.LastPath != seeded.LastPath {
		t.Fatalf("canceled run advanced cursor: %q -> %q", seeded.LastPath, after.LastPath)
	}
}

// Case 6: wrap. Drive enough cycles to wrap the cursor; assert WrappedAt and
// LastFullCycleTS are set and coverage continues from the start.
func TestRollingContentWrapSetsTimestamps(t *testing.T) {
	resetPHPContentScanCounts(t)
	fx := newRollingFixture(t)
	withMockOS(t, rollingRootOS{root: fx.root})
	db := useRollingStore(t)

	cfg := rollingCfg(4) // 6 custom files: cycle1 covers 4, cycle2 covers 2 then wraps to cover 2 more
	ctx := context.Background()

	var wrapped bool
	// At most a handful of cycles are needed to wrap a 6-file set with cap 4.
	for i := 0; i < 4 && !wrapped; i++ {
		_ = CheckPHPContent(ctx, cfg, nil)
		cur, ok, _ := db.GetScanCursor(fx.account, "php_content")
		if !ok {
			t.Fatalf("cycle %d: cursor missing", i+1)
		}
		if !cur.WrappedAt.IsZero() {
			wrapped = true
			if cur.LastFullCycleTS.IsZero() {
				t.Fatal("wrap set WrappedAt but not LastFullCycleTS")
			}
		}
	}
	if !wrapped {
		t.Fatal("cursor never wrapped after enough cycles to cover the full set")
	}
}

func TestRollingContentSingleSliceSetsLastFullCycle(t *testing.T) {
	resetPHPContentScanCounts(t)
	fx := newRollingFixture(t)
	withMockOS(t, rollingRootOS{root: fx.root})
	db := useRollingStore(t)

	cfg := rollingCfg(100)
	_ = CheckPHPContent(context.Background(), cfg, nil)

	cur, ok, _ := db.GetScanCursor(fx.account, "php_content")
	if !ok {
		t.Fatal("cursor missing after rolling scan")
	}
	if cur.LastFullCycleTS.IsZero() {
		t.Fatal("single-slice rolling scan must mark the account's full cycle complete")
	}
	if !cur.WrappedAt.IsZero() {
		t.Fatal("single-slice rolling scan must not claim a cursor wrap")
	}
}

func TestRollingContentReportsCursorWriteError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.php"), rollingBenignPHP)

	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() { store.SetGlobal(prev) })
	if err := db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	cfg := rollingCfg(1)
	scan := newPHPContentScan(cfg, nil, false)
	var findings []alert.Finding
	stderr := captureStderr(t, func() {
		rollingContentCoverage(context.Background(), cfg, scan, "acct", []string{dir}, &findings)
	})
	if !strings.Contains(stderr, "php_content rolling: cursor write for acct:") {
		t.Fatalf("cursor write error was not reported; stderr=%q", stderr)
	}
}

func TestRollingContentSkipsNonRegularCandidates(t *testing.T) {
	db := useRollingStore(t)

	dir := "/home/acct/public_html"
	pipePath := filepath.Join(dir, "pipe.php")
	opened := false
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == dir {
				return []os.DirEntry{testDirEntry{name: "pipe.php"}}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == pipePath {
				return fakeFileInfoWithMode{name: "pipe.php", mode: os.ModeNamedPipe}, nil
			}
			return nil, os.ErrNotExist
		},
		open: func(string) (*os.File, error) {
			opened = true
			return nil, os.ErrPermission
		},
	})

	cfg := rollingCfg(1)
	scan := newPHPContentScan(cfg, nil, false)
	var findings []alert.Finding
	rollingContentCoverage(context.Background(), cfg, scan, "acct", []string{dir}, &findings)

	if opened {
		t.Fatal("rolling content must not open non-regular PHP candidates")
	}
	if len(findings) != 0 {
		t.Fatalf("non-regular candidate produced findings: %+v", findings)
	}
	cur, ok, err := db.GetScanCursor("acct", "php_content")
	if err != nil {
		t.Fatalf("GetScanCursor: %v", err)
	}
	if !ok || cur.LastPath != pipePath {
		t.Fatalf("cursor must advance past non-regular candidates, got ok=%v last=%q", ok, cur.LastPath)
	}
}

// Case 7: nil store -> rolling is a no-op (no panic), normal suspicious-dir scan
// still runs.
func TestRollingContentNilStoreIsNoOp(t *testing.T) {
	resetPHPContentScanCounts(t)
	fx := newRollingFixture(t)
	withMockOS(t, rollingRootOS{root: fx.root})

	prev := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(prev) })

	cfg := rollingCfg(2)
	// Must not panic. The dormant file is out of the suspicious dirs and the
	// cursor cannot persist, so rolling is skipped -- the dormant file is not
	// found, but the call completes cleanly.
	got := CheckPHPContent(context.Background(), cfg, nil)
	if findsPath(got, fx.dormant) {
		t.Fatal("nil store: rolling must be skipped, dormant file not swept")
	}
}

// Case 8: scanDir parity after the scanFile extraction. A malicious file inside
// a directly-scanned dir is still detected by scanDir (proves the per-file
// extraction is behavior-preserving). The broader php_content suite is the full
// parity guard; this is a focused smoke check living with the rolling tests.
func TestScanFileExtractionParity(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	path := filepath.Join(dir, "shell.php")
	writeFile(t, path, rollingDormantPHP)

	s := newPHPContentScan(cfg, nil, false)
	var findings []alert.Finding
	s.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &findings)
	if !findsPath(findings, path) {
		t.Fatal("scanDir must still detect a malicious file after scanFile extraction")
	}
}
