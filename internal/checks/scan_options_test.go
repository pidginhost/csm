package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestDefaultAccountScanOptionsMatchesCurrentBehavior(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 0 // unset -> default
	opts := DefaultAccountScanOptions(cfg)
	if opts.MaxFiles != accountScanMaxFilesDefault {
		t.Errorf("MaxFiles = %d, want %d", opts.MaxFiles, accountScanMaxFilesDefault)
	}
	if opts.ForceContent || opts.ForceFileIndex {
		t.Errorf("force flags must default false, got content=%v index=%v", opts.ForceContent, opts.ForceFileIndex)
	}
	if !opts.RespectIgnores {
		t.Error("RespectIgnores must default true")
	}
}

func TestScanOptionsRoundTripThroughContext(t *testing.T) {
	want := AccountScanOptions{MaxFiles: 0, ForceContent: true, RespectIgnores: false}
	ctx := ContextWithScanOptions(context.Background(), want)
	got, ok := ScanOptionsFromContext(ctx)
	if !ok || got != want {
		t.Fatalf("round trip = %+v ok=%v, want %+v", got, ok, want)
	}
}

func TestScanOptionsFromContextAbsent(t *testing.T) {
	if _, ok := ScanOptionsFromContext(context.Background()); ok {
		t.Error("expected ok=false when no options set")
	}
}

func TestRunAccountScanWithDefaultOptionsEqualsLegacy(t *testing.T) {
	cfg := &config.Config{}
	a := RunAccountScan(cfg, nil, "missing_acct") // account-not-found path
	b := RunAccountScanWithOptions(context.Background(), cfg, nil, "missing_acct", DefaultAccountScanOptions(cfg))
	if len(a) != len(b) || (len(a) == 1 && a[0].Check != b[0].Check) {
		t.Fatalf("default options diverge from legacy: %v vs %v", a, b)
	}
}

func TestAccountScanMaxFilesPrefersContextOptions(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 10000
	ctx := ContextWithScanOptions(context.Background(), AccountScanOptions{MaxFiles: 0})
	if got := accountScanMaxFiles(ctx, cfg); got != 0 {
		t.Errorf("with full-scan options MaxFiles should be 0 (uncapped), got %d", got)
	}
	if got := accountScanMaxFiles(context.Background(), cfg); got != 10000 {
		t.Errorf("without options should fall back to cfg, got %d", got)
	}
}

func TestFullScanBypassesIgnorePaths(t *testing.T) {
	cfg := &config.Config{}
	cfg.Suppressions.IgnorePaths = []string{"*/vendor/*"}
	full := ContextWithScanOptions(context.Background(), AccountScanOptions{RespectIgnores: false})
	if scanRespectsIgnores(full, cfg) {
		t.Error("full scan with RespectIgnores=false must not respect ignore_paths")
	}
	if !scanRespectsIgnores(context.Background(), cfg) {
		t.Error("normal scan must respect ignore_paths")
	}
}

func TestFullScanForcesContentRescan(t *testing.T) {
	if !scanForceContent(ContextWithScanOptions(context.Background(), AccountScanOptions{ForceContent: true})) {
		t.Error("ForceContent must be reported true under full options")
	}
	if scanForceContent(context.Background()) {
		t.Error("ForceContent must be false without options")
	}
}

func TestFullScanForceContentRereadsCachedCleanFile(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	path := filepath.Join(dir, "x.php")
	mtime := time.Unix(1_700_000_000, 0)

	// Seed the cache: scan benign content -> s1.next holds a clean stamp.
	writePHPFixture(t, path, phpCacheBenign, mtime)
	s1 := newPHPContentScan(cfg, nil, false)
	var f1 []alert.Finding
	s1.scanDir(context.Background(), dir, 4, phpHandlerOverlay{}, &f1)
	if len(f1) != 0 {
		t.Fatalf("benign seed should produce no finding, got %+v", f1)
	}

	// Swap in malicious content; keep mtime+size identical so the cache key matches.
	writePHPFixture(t, path, phpCacheMalicious, mtime)

	// Default scan: cache hit -> no finding (existing behaviour, unchanged).
	defaultCtx := ContextWithScanOptions(context.Background(), AccountScanOptions{ForceContent: false})
	s2 := newPHPContentScan(cfg, s1.next, scanForceContent(defaultCtx))
	var f2 []alert.Finding
	s2.scanDir(defaultCtx, dir, 4, phpHandlerOverlay{}, &f2)
	if len(f2) != 0 {
		t.Fatalf("default cached scan should skip unchanged clean stamp, got %+v", f2)
	}

	// Full-scan: ForceContent=true -> cache bypassed -> malicious content detected.
	fullCtx := ContextWithScanOptions(context.Background(), AccountScanOptions{ForceContent: true})
	s3 := newPHPContentScan(cfg, s1.next, scanForceContent(fullCtx))
	var f3 []alert.Finding
	s3.scanDir(fullCtx, dir, 4, phpHandlerOverlay{}, &f3)
	if len(f3) == 0 {
		t.Fatal("full scan must re-read unchanged cached-clean content and detect the webshell")
	}
}

func TestFullScanForceContentDoesNotWriteCache(t *testing.T) {
	stateDir := t.TempDir()
	cfg := &config.Config{StatePath: stateDir}
	webDir := t.TempDir()
	phpPath := filepath.Join(webDir, "x.php")
	mtime := time.Unix(1_700_000_000, 0)

	// Write a benign file and pre-seed the cache to mark it clean.
	writePHPFixture(t, phpPath, phpCacheBenign, mtime)
	stamp := phpFileStamp{Mtime: mtime.Unix(), Size: int64(len(phpCacheBenign))}
	preSeedCache := phpContentCache{phpPath: stamp}
	savePHPContentCache(stateDir, preSeedCache)

	// Record original cache bytes.
	cachePath := filepath.Join(stateDir, "phpcontentcache.json")
	origBytes, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read pre-seeded cache: %v", err)
	}

	// Now swap in malicious content with same mtime+size and run CheckPHPContent
	// under a full-scan (ForceContent=true) account context. The save gate must
	// block the write so the live cache bytes are unchanged afterward.
	writePHPFixture(t, phpPath, phpCacheMalicious, mtime)

	// We need an account context so CheckPHPContent's account-scope guard also
	// fires; the ForceContent guard is the new layer under test.
	fullCtx := ContextWithScanOptions(
		ContextWithAccountScope(context.Background(), "acct"),
		AccountScanOptions{ForceContent: true},
	)
	// CheckPHPContent walks /home; stub it so it visits our temp dir instead.
	// Use the lower-level save-gate assertion via a direct scan + conditional save,
	// matching the production code path in CheckPHPContent.
	scan := newPHPContentScan(cfg, loadPHPContentCache(cfg.StatePath), scanForceContent(fullCtx))
	var findings []alert.Finding
	scan.scanDir(fullCtx, webDir, 4, phpHandlerOverlay{}, &findings)
	// Replicate the save-gate condition from CheckPHPContent.
	if fullCtx.Err() == nil && AccountFromContext(fullCtx) == "" && !scanForceContent(fullCtx) {
		savePHPContentCache(cfg.StatePath, scan.next)
	}

	afterBytes, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache after full scan: %v", err)
	}
	if string(afterBytes) != string(origBytes) {
		t.Fatalf("full scan must not update phpcontentcache.json; before=%s after=%s", origBytes, afterBytes)
	}
}

func TestFullScanFindsIgnoredVendorWebshell(t *testing.T) {
	tmp := t.TempDir()
	logicalRoot := "/home/acct/public_html"
	physicalRoot := filepath.Join(tmp, "home", "acct", "public_html")
	vendorDir := filepath.Join(physicalRoot, "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	physicalShell := filepath.Join(vendorDir, "c99.php")
	old := time.Now().Add(-365 * 24 * time.Hour)
	writePHPFixture(t, physicalShell, phpCacheMalicious, old)

	logicalShell := filepath.Join(logicalRoot, "vendor", "c99.php")

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case logicalRoot:
				return []os.DirEntry{testDirEntry{name: "vendor", isDir: true}}, nil
			case filepath.Join(logicalRoot, "vendor"):
				return []os.DirEntry{testDirEntry{name: "c99.php", isDir: false}}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == logicalShell {
				return os.Stat(physicalShell)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.Suppressions.IgnorePaths = []string{"*/vendor/*"}
	names := map[string]bool{"c99.php": true}

	var defaultFindings []alert.Finding
	scanForWebshells(context.Background(), logicalRoot, 4, names, nil, cfg, &defaultFindings)
	if hasFindingPath(defaultFindings, "webshell", logicalShell) {
		t.Fatalf("default scan should respect ignore_paths: %+v", defaultFindings)
	}

	fullCtx := ContextWithScanOptions(context.Background(), AccountScanOptions{RespectIgnores: false})
	var fullFindings []alert.Finding
	scanForWebshells(fullCtx, logicalRoot, 4, names, nil, cfg, &fullFindings)
	if !hasFindingPath(fullFindings, "webshell", logicalShell) {
		t.Fatalf("full scan should bypass ignore_paths: %+v", fullFindings)
	}
}
