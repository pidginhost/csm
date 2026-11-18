package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// kmodScenario baselines ext4, records the previous scan at lastScanAgo,
// stamps a package-manager log at pkgAgo (negative: no log), then lists
// ext4 plus newMod and returns the findings of that second scan.
func kmodScenario(t *testing.T, newMod string, lastScanAgo, pkgAgo time.Duration) []alert.Finding {
	t.Helper()
	modules := "ext4 720896 1 - Live\n"
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name != "/proc/modules" {
				return nil, os.ErrNotExist
			}
			p := filepath.Join(t.TempDir(), "modules")
			if err := os.WriteFile(p, []byte(modules), 0o600); err != nil {
				t.Fatal(err)
			}
			return os.Open(p)
		},
	})

	logPath := filepath.Join(t.TempDir(), "dpkg.log")
	oldFiles := kmodPkgTransactionFiles
	kmodPkgTransactionFiles = []string{logPath}
	t.Cleanup(func() { kmodPkgTransactionFiles = oldFiles })
	now := time.Now()
	if pkgAgo >= 0 {
		if err := os.WriteFile(logPath, []byte("status installed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		at := now.Add(-pkgAgo)
		if err := os.Chtimes(logPath, at, at); err != nil {
			t.Fatal(err)
		}
	}

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if f := CheckKernelModules(context.Background(), &config.Config{}, store); len(f) != 0 {
		t.Fatalf("baseline run produced findings: %+v", f)
	}
	store.SetRaw(kmodLastScanKey, now.Add(-lastScanAgo).UTC().Format(time.RFC3339Nano))

	modules += newMod + " 16384 0 - Live\n"
	return CheckKernelModules(context.Background(), &config.Config{}, store)
}

func TestCheckKernelModulesPackageUpgradeBetweenScansIsWarning(t *testing.T) {
	// apt finished 9 minutes before the scan that first saw af_alg, as on a
	// host where the critical tier runs every 10 minutes.
	findings := kmodScenario(t, "af_alg", 10*time.Minute, 9*time.Minute)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %+v", findings)
	}
	f := findings[0]
	if f.Severity != alert.Warning {
		t.Errorf("severity = %v, want Warning", f.Severity)
	}
	if !strings.Contains(f.Details, "package manager") {
		t.Errorf("details do not name the demotion: %q", f.Details)
	}
}

func TestCheckKernelModulesNoPackageActivityStaysHigh(t *testing.T) {
	findings := kmodScenario(t, "rootkit", 10*time.Minute, 2*time.Hour)
	if len(findings) != 1 || findings[0].Severity != alert.High {
		t.Fatalf("want one High finding, got %+v", findings)
	}
}

func TestCheckKernelModulesNoPackageLogStaysHigh(t *testing.T) {
	findings := kmodScenario(t, "rootkit", 10*time.Minute, -1)
	if len(findings) != 1 || findings[0].Severity != alert.High {
		t.Fatalf("want one High finding, got %+v", findings)
	}
}

func TestCheckKernelModulesCopyFailModuleNeverDemoted(t *testing.T) {
	findings := kmodScenario(t, "algif_aead", 10*time.Minute, time.Minute)
	if len(findings) != 1 || findings[0].Severity != alert.High {
		t.Fatalf("algif_aead must stay High during package activity, got %+v", findings)
	}
}

func TestCheckKernelModulesStaleLastScanIsClamped(t *testing.T) {
	// The daemon was down for hours; an upgrade an hour ago must not excuse
	// a module first seen now.
	findings := kmodScenario(t, "rootkit", 3*time.Hour, time.Hour)
	if len(findings) != 1 || findings[0].Severity != alert.High {
		t.Fatalf("want one High finding, got %+v", findings)
	}
}

func TestKmodPkgCutoff(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	now := time.Date(2026, 11, 18, 16, 0, 32, 0, time.UTC)

	if got, want := kmodPkgCutoff(store, now), now.Add(-pkgWindowDefault); !got.Equal(want) {
		t.Errorf("no previous scan: cutoff = %v, want %v", got, want)
	}

	last := now.Add(-10 * time.Minute)
	store.SetRaw(kmodLastScanKey, last.Format(time.RFC3339Nano))
	if got := kmodPkgCutoff(store, now); !got.Equal(last) {
		t.Errorf("recent scan: cutoff = %v, want %v", got, last)
	}

	store.SetRaw(kmodLastScanKey, now.Add(-5*time.Hour).Format(time.RFC3339Nano))
	if got, want := kmodPkgCutoff(store, now), now.Add(-kmodPkgWindowMax); !got.Equal(want) {
		t.Errorf("stale scan: cutoff = %v, want %v", got, want)
	}

	store.SetRaw(kmodLastScanKey, now.Add(time.Hour).Format(time.RFC3339Nano))
	if got, want := kmodPkgCutoff(store, now), now.Add(-pkgWindowDefault); !got.Equal(want) {
		t.Errorf("future scan: cutoff = %v, want %v", got, want)
	}

	store.SetRaw(kmodLastScanKey, "garbage")
	if got, want := kmodPkgCutoff(store, now), now.Add(-pkgWindowDefault); !got.Equal(want) {
		t.Errorf("unparsable scan: cutoff = %v, want %v", got, want)
	}
}

func TestCheckKernelModulesMetadataRefreshStaysHigh(t *testing.T) {
	// dnf makecache rewrites dnf.log and dnf.rpm.log hourly without
	// installing anything; that must not excuse a new module.
	dnfLog := filepath.Join(t.TempDir(), "dnf.log")
	if err := os.WriteFile(dnfLog, []byte("Metadata cache created.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldLogs := pkgManagerLogs
	pkgManagerLogs = []string{dnfLog}
	t.Cleanup(func() { pkgManagerLogs = oldLogs })

	findings := kmodScenario(t, "rootkit", 10*time.Minute, -1)
	if len(findings) != 1 || findings[0].Severity != alert.High {
		t.Fatalf("want one High finding, got %+v", findings)
	}
}
