package checks

import (
	"context"
	"testing"

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
