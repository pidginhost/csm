package checks

import (
	"bytes"
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
	if opts.MaxFileBytes != 0 {
		t.Errorf("MaxFileBytes must default 0 (use per-check limits), got %d", opts.MaxFileBytes)
	}
	if got := scanMaxFileBytes(context.Background()); got != 0 {
		t.Errorf("scanMaxFileBytes(Background()) = %d, want 0", got)
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
	resetPHPContentScanCounts(t)
	stateDir := t.TempDir()
	cfg := &config.Config{StatePath: stateDir}
	cachePath := filepath.Join(stateDir, "phpcontentcache.json")

	// Stub the filesystem so CheckPHPContent can complete without a real /home.
	// /home has one account directory; all subdirectory reads return empty so no
	// PHP files are visited. No readFile hook is set, so loadPHPContentCache
	// sees ErrNotExist and starts with an empty prior cache.
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "acct", isDir: true}}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	// Host-scope context (no ContextWithAccountScope, so AccountFromContext=="")
	// with ForceContent=true. The save gate in CheckPHPContent is:
	//   ctx.Err()==nil && AccountFromContext(ctx)==""  && !scanForceContent(ctx)
	// The first two clauses are true; only !scanForceContent(ctx) blocks the
	// write. If that clause is removed from production, savePHPContentCache is
	// called and the file is created -- this test then fails as required.
	fullCtx := ContextWithScanOptions(context.Background(), AccountScanOptions{ForceContent: true})
	CheckPHPContent(fullCtx, cfg, nil)

	if _, err := os.Stat(cachePath); err == nil {
		t.Fatal("CheckPHPContent with ForceContent=true must not write phpcontentcache.json")
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

func TestFullScanOversizedPHPEmitsJobWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.php")
	body := append([]byte("<?php "), bytes.Repeat([]byte("A"), 64)...)
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}

	ctx := ContextWithScanOptions(context.Background(), AccountScanOptions{
		ForceContent: true,
		MaxFileBytes: 8,
	})
	var findings []alert.Finding
	newPHPContentScan(&config.Config{}, nil, true).scanDir(ctx, dir, 1, phpHandlerOverlay{}, &findings)
	if !hasFindingPath(findings, "full_scan_file_too_large", path) {
		t.Fatalf("oversized full-scan PHP file did not produce warning: %+v", findings)
	}
}

func TestFullScanMaxFileBytesDefault(t *testing.T) {
	if got := FullScanMaxFileBytes(&config.Config{}); got != 16*1024*1024 {
		t.Errorf("FullScanMaxFileBytes default = %d, want 16 MiB", got)
	}
	cfg := &config.Config{}
	cfg.Thresholds.FullScanMaxFileMB = 32
	if got := FullScanMaxFileBytes(cfg); got != 32*1024*1024 {
		t.Errorf("FullScanMaxFileBytes override = %d, want 32 MiB", got)
	}
}
