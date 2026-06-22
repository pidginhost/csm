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

func TestCheckFilesystemBackdoorRankingFiltersNonCandidateBeforeStat(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Date(2026, 5, 22, 18, 0, 0, 0, time.UTC)
	noise := "/home/aaa-customer/.config/htop/htoprc"
	backdoor := "/home/zzz-customer/.config/htop/defunct"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/.config/htop/*" {
				return []string{noise, backdoor}, nil
			}
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == noise {
				cancel()
				return statWithMtime{name: "htoprc", modTime: now.Add(time.Minute)}, nil
			}
			if name == backdoor {
				return statWithMtime{name: "defunct", modTime: now}, nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})

	findings := CheckFilesystem(ctx, nil, nil)
	if !hasFindingPath(findings, "backdoor_binary", backdoor) {
		t.Fatalf("expected backdoor finding for %s, got %+v", backdoor, findings)
	}
}

func TestCheckFilesystemHiddenRankingSkipsSafePrefixesBeforeStat(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Date(2026, 5, 22, 18, 0, 0, 0, time.UTC)
	safe := "/tmp/.font-unix"
	suspicious := "/tmp/.malware_payload"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/tmp/.*" {
				return []string{safe, suspicious}, nil
			}
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == safe {
				cancel()
				return statWithMtime{name: ".font-unix", modTime: now.Add(time.Minute)}, nil
			}
			if name == suspicious {
				return statWithMtime{name: ".malware_payload", modTime: now}, nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})

	findings := CheckFilesystem(ctx, nil, nil)
	if !hasFindingPath(findings, "suspicious_file", suspicious) {
		t.Fatalf("expected suspicious hidden-file finding for %s, got %+v", suspicious, findings)
	}
}

func TestCheckFilesystemBackdoorCapAppliesAcrossConfigGlobs(t *testing.T) {
	now := time.Date(2026, 5, 22, 18, 0, 0, 0, time.UTC)
	oldPath := "/home/aaa-customer/.config/htop/defunct"
	recentPath := "/home/zzz-customer/.config/gsocket/gs-netcat"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/home/*/.config/htop/*":
				return []string{oldPath}, nil
			case "/home/*/.config/*/*":
				return []string{oldPath, recentPath}, nil
			default:
				return nil, nil
			}
		},
		stat: mtimesByPath(map[string]time.Time{
			oldPath:    now.Add(-24 * time.Hour),
			recentPath: now.Add(-1 * time.Minute),
		}),
		readDir: func(name string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})

	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 1
	findings := CheckFilesystem(context.Background(), cfg, nil)

	backdoorPaths := findingPaths(findings, "backdoor_binary")
	if len(backdoorPaths) != 1 {
		t.Fatalf("backdoor findings = %v, want exactly [%s]", backdoorPaths, recentPath)
	}
	if backdoorPaths[0] != recentPath {
		t.Fatalf("backdoor findings = %v, want recent late-alphabet path %s", backdoorPaths, recentPath)
	}
}

func TestCheckFilesystemHiddenFilesIgnoreAccountScanCap(t *testing.T) {
	now := time.Date(2026, 5, 22, 18, 0, 0, 0, time.UTC)
	oldPath := "/tmp/.old_payload"
	recentPath := "/tmp/.recent_payload"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/tmp/.*" {
				return []string{oldPath, recentPath}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{
			oldPath:    now.Add(-24 * time.Hour),
			recentPath: now.Add(-1 * time.Minute),
		}),
		readDir: func(name string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})

	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 1
	findings := CheckFilesystem(context.Background(), cfg, nil)

	if !hasFindingPath(findings, "suspicious_file", oldPath) {
		t.Fatalf("old global hidden file was capped by account_scan_max_files: %+v", findings)
	}
	if !hasFindingPath(findings, "suspicious_file", recentPath) {
		t.Fatalf("recent global hidden file missing: %+v", findings)
	}
}

func TestCheckFilesystemCanceledDuringFinalHiddenRankDoesNotReadHome(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	suspicious := "/var/tmp/.malware_payload"
	homeRead := false

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/var/tmp/.*" {
				return []string{suspicious}, nil
			}
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == suspicious {
				cancel()
				return statWithMtime{name: ".malware_payload", modTime: time.Now()}, nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				homeRead = true
			}
			return nil, os.ErrNotExist
		},
	})

	_ = CheckFilesystem(ctx, nil, nil)
	if homeRead {
		t.Fatal("CheckFilesystem read /home after cancellation during hidden-file mtime ranking")
	}
}

func TestFullScanFindsOldCapDroppedFilesystemCandidate(t *testing.T) {
	tmp := t.TempDir()
	account := "acct"
	logicalHome := "/home/" + account
	physicalHome := filepath.Join(tmp, "home", account)
	if err := os.MkdirAll(physicalHome, 0755); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	logicalToPhysical := map[string]string{}
	writeCandidate := func(rel string, when time.Time) string {
		t.Helper()
		logical := filepath.Join(logicalHome, rel)
		physical := filepath.Join(physicalHome, rel)
		if err := os.MkdirAll(filepath.Dir(physical), 0755); err != nil {
			t.Fatal(err)
		}
		writePHPFixture(t, physical, phpCacheMalicious, when)
		logicalToPhysical[logical] = physical
		return logical
	}

	recentA := writeCandidate(filepath.Join(".config", "htop", "defunct"), now.Add(-1*time.Minute))
	recentB := writeCandidate(filepath.Join(".config", "agent", "defunct.dat"), now.Add(-2*time.Minute))
	old := writeCandidate(filepath.Join(".config", "agent", "gsocket"), now.Add(-365*24*time.Hour))

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case filepath.Join(logicalHome, ".config", "htop", "*"),
				filepath.Join(logicalHome, ".config", "*", "*"):
				return []string{recentA, recentB, old}, nil
			default:
				return nil, nil
			}
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == logicalHome {
				return os.Stat(physicalHome)
			}
			if physical, ok := logicalToPhysical[name]; ok {
				return os.Stat(physical)
			}
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == logicalHome {
				return nil, nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 2
	defaultCtx := ContextWithAccountScope(context.Background(), account)
	if findings := CheckFilesystem(defaultCtx, cfg, nil); hasFindingPath(findings, "backdoor_binary", old) {
		t.Fatalf("default capped scan found old path beyond cap: %+v", findings)
	}

	fullCtx := ContextWithScanOptions(defaultCtx, AccountScanOptions{MaxFiles: 0, RespectIgnores: true})
	if findings := CheckFilesystem(fullCtx, cfg, nil); !hasFindingPath(findings, "backdoor_binary", old) {
		t.Fatalf("full scan missed old path beyond cap: %+v", findings)
	}
}

func hasFindingPath(findings []alert.Finding, check, path string) bool {
	for _, finding := range findings {
		if finding.Check == check && finding.FilePath == path {
			return true
		}
	}
	return false
}

func findingPaths(findings []alert.Finding, check string) []string {
	var paths []string
	for _, finding := range findings {
		if finding.Check == check {
			paths = append(paths, finding.FilePath)
		}
	}
	return paths
}
