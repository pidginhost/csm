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
