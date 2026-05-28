package checks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestEffectiveAccountScanMaxFiles(t *testing.T) {
	if got := effectiveAccountScanMaxFiles(nil); got != accountScanMaxFilesDefault {
		t.Errorf("nil cfg -> %d, want %d", got, accountScanMaxFilesDefault)
	}

	cfg := &config.Config{}
	if got := effectiveAccountScanMaxFiles(cfg); got != accountScanMaxFilesDefault {
		t.Errorf("zero cfg -> %d, want %d", got, accountScanMaxFilesDefault)
	}

	cfg.Thresholds.AccountScanMaxFiles = -1
	if got := effectiveAccountScanMaxFiles(cfg); got != accountScanMaxFilesDefault {
		t.Errorf("negative cfg -> %d, want %d", got, accountScanMaxFilesDefault)
	}

	cfg.Thresholds.AccountScanMaxFiles = 42
	if got := effectiveAccountScanMaxFiles(cfg); got != 42 {
		t.Errorf("configured cfg -> %d, want 42", got)
	}
}

func TestRunParallelReturnsAccountScanTruncationFinding(t *testing.T) {
	now := time.Now()
	paths := []string{
		"/home/aaa-customer/wp-config.php",
		"/home/bbb-customer/wp-config.php",
		"/home/zzz-customer/wp-config.php",
	}
	withMockOS(t, &mockOS{stat: mtimesByPath(map[string]time.Time{
		paths[0]: now.Add(-24 * time.Hour),
		paths[1]: now.Add(-12 * time.Hour),
		paths[2]: now.Add(-1 * time.Minute),
	})})

	checks := []namedCheck{{
		name: "unit_account_scan_cap",
		fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			got := rankPathsByMtimeDesc(ctx, paths, 1)
			if len(got) != 1 || got[0] != paths[2] {
				t.Fatalf("ranked paths = %v, want only %q", got, paths[2])
			}
			return nil
		},
	}}

	findings, _ := runParallel(&config.Config{}, nil, checks, "unit", true)
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2: %+v", len(findings), findings)
	}
	byTenant := map[string]alert.Finding{}
	for _, f := range findings {
		if f.Check != "account_scan_truncated" || f.Severity != alert.Warning {
			t.Fatalf("finding = %+v, want warning account_scan_truncated", f)
		}
		if f.Timestamp.IsZero() {
			t.Fatal("timestamp is zero")
		}
		byTenant[f.TenantID] = f
	}
	for _, tenant := range []string{"aaa-customer", "bbb-customer"} {
		f, ok := byTenant[tenant]
		if !ok {
			t.Fatalf("missing truncation finding for %s: %+v", tenant, findings)
		}
		if !strings.Contains(f.Message, tenant) || !strings.Contains(f.Message, "1 file(s) skipped past cap of 1") {
			t.Fatalf("message = %q, want tenant name, skipped count, and cap", f.Message)
		}
	}
}

func TestCheckSSHKeysUsesAccountScanMaxFilesAfterMtimeRank(t *testing.T) {
	now := time.Now()
	oldPath := "/home/aaa-customer/.ssh/authorized_keys"
	recentPath := "/home/zzz-customer/.ssh/authorized_keys"
	paths := []string{oldPath, recentPath}

	readPaths := []string{}
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/.ssh/authorized_keys" {
				return paths, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{
			oldPath:    now.Add(-24 * time.Hour),
			recentPath: now.Add(-1 * time.Minute),
		}),
		readFile: func(name string) ([]byte, error) {
			readPaths = append(readPaths, name)
			switch name {
			case oldPath:
				return []byte("old-new-key"), nil
			case recentPath:
				return []byte("recent-new-key"), nil
			default:
				return nil, os.ErrNotExist
			}
		},
	})

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	st.SetRaw("_ssh_user_keys:"+oldPath, hashBytes([]byte("old-key")))
	st.SetRaw("_ssh_user_keys:"+recentPath, hashBytes([]byte("recent-old-key")))

	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 1

	findings := CheckSSHKeys(context.Background(), cfg, st)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, recentPath) {
		t.Fatalf("finding = %+v, want recent late-alphabet path %q", findings[0], recentPath)
	}
	for _, path := range readPaths {
		if path == oldPath {
			t.Fatalf("old lex-first path was read despite account_scan_max_files=1; reads=%v", readPaths)
		}
	}
}

func TestDiscoverShadowFilesUsesMtimeRankBeforeCap(t *testing.T) {
	now := time.Now()
	oldPath := "/home/aaa-customer/etc/example.com/shadow"
	recentPath := "/home/zzz-customer/etc/example.net/shadow"
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/etc/*/shadow" {
				return []string{oldPath, recentPath}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{
			oldPath:    now.Add(-24 * time.Hour),
			recentPath: now.Add(-1 * time.Minute),
		}),
	})

	got := discoverShadowFiles(context.Background(), 1)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1: %+v", len(got), got)
	}
	if got[0].path != recentPath || got[0].account != "zzz-customer" || got[0].domain != "example.net" {
		t.Fatalf("got %+v, want recent late-alphabet shadow file %q", got[0], recentPath)
	}
}
