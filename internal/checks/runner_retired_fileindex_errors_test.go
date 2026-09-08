package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestRetiredFileIndexNamesSurviveReadErrors(t *testing.T) {
	for _, initial := range []struct {
		name  string
		scans int32
	}{{"startup", 0}, {"periodic", 5}} {
		for _, failure := range []string{"root", "partial-root", "home", "languages", "upgrade", "uploads", "config", "tmp", "addon-stat", "addon-uploads-stat", "htaccess"} {
			t.Run(initial.name+"/"+failure, func(t *testing.T) {
				previousCount := atomic.LoadInt32(&fileIndexScanCount)
				atomic.StoreInt32(&fileIndexScanCount, initial.scans)
				t.Cleanup(func() { atomic.StoreInt32(&fileIndexScanCount, previousCount) })
				base := t.TempDir()
				homes := filepath.Join(base, "homes")
				home := filepath.Join(homes, "alice")
				webroot := filepath.Join(home, "public_html")
				if strings.HasPrefix(failure, "addon-") {
					webroot = filepath.Join(home, "addon")
				}
				languages := filepath.Join(webroot, "wp-content", "languages")
				upgrade := filepath.Join(webroot, "wp-content", "upgrade")
				rows := []alert.Finding{
					{Check: "new_php_in_languages", Severity: alert.Critical, FilePath: filepath.Join(languages, "index.php")},
					{Check: "new_php_in_upgrade", Severity: alert.Critical, FilePath: filepath.Join(upgrade, "index.php")},
				}
				for _, row := range rows {
					if err := os.MkdirAll(filepath.Dir(row.FilePath), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(row.FilePath, []byte("<?php // Silence is golden.\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				withAccountHomeRoots(t, homes)
				var freshPath string
				if failure == "partial-root" {
					otherHomes := filepath.Join(base, "other-homes")
					freshPath = filepath.Join(otherHomes, "bob", "public_html", "wp-content", "uploads", "c99.php")
					if err := os.MkdirAll(filepath.Dir(freshPath), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(freshPath, []byte("<?php eval($_POST['code']);\n"), 0600); err != nil {
						t.Fatal(err)
					}
					withAccountHomeRoots(t, homes, otherHomes)
				}
				st, err := state.Open(filepath.Join(base, "state"))
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = st.Close() }()
				st.SetLatestFindings(rows)
				index := rows[0].FilePath + "\n" + rows[1].FilePath + "\n"
				cache := make(dirMtimeCache)
				for _, path := range []string{languages, upgrade} {
					info, statErr := os.Stat(path)
					if statErr != nil {
						t.Fatal(statErr)
					}
					cache[path] = info.ModTime().Unix()
				}
				cacheJSON, err := json.Marshal(cache)
				if err != nil {
					t.Fatal(err)
				}
				before := map[string]string{
					"fileindex.previous": index, "fileindex.current": index, "dircache.json": string(cacheJSON),
				}
				for name, contents := range before {
					if err := os.WriteFile(filepath.Join(base, "state", name), []byte(contents), 0600); err != nil {
						t.Fatal(err)
					}
				}
				failedPath := map[string]string{
					"root": homes, "partial-root": homes, "home": home, "languages": languages,
					"upgrade": upgrade, "addon-stat": languages, "uploads": filepath.Join(webroot, "wp-content", "uploads"),
					"config": filepath.Join(home, ".config"), "tmp": "/tmp",
					"addon-uploads-stat": filepath.Join(webroot, "wp-content", "uploads"),
					"htaccess":           filepath.Join(languages, ".htaccess"),
				}[failure]
				withMockOS(t, &mockOS{
					readDir: func(path string) ([]os.DirEntry, error) {
						if !strings.HasPrefix(failure, "addon-") && path == failedPath {
							return nil, os.ErrPermission
						}
						if !strings.HasPrefix(path, base+string(filepath.Separator)) {
							return nil, os.ErrNotExist
						}
						return os.ReadDir(path)
					},
					stat: func(path string) (os.FileInfo, error) {
						if strings.HasPrefix(failure, "addon-") && path == failedPath {
							return nil, os.ErrPermission
						}
						return os.Stat(path)
					},
					readFile: func(path string) ([]byte, error) {
						if failure == "htaccess" && path == failedPath {
							return nil, os.ErrPermission
						}
						return os.ReadFile(path)
					},
					open: os.Open, lstat: os.Lstat,
				})
				cfg := &config.Config{StatePath: filepath.Join(base, "state")}
				// Retry with unchanged directory mtimes: a failed walk must not
				// publish a cache that makes the next attempt look complete.
				for attempt := 0; attempt < 3; attempt++ {
					ctx, gaps := WithCoverageGaps(context.Background())
					if attempt == 0 {
						// Direct callers also must not publish a partial cache.
						CheckFileIndex(ctx, cfg, st)
					} else {
						findings, purge := runParallelWithContext(ctx, cfg, st,
							[]namedCheck{{name: "file_index", fn: CheckFileIndex}}, "deep", true)
						StoreLatestScanFindingsWithGaps(st, purge, findings, gaps.Paths())
					}
					got := st.LatestFindings()
					if attempt > 0 && freshPath != "" && !hasFindingPath(got, "new_webshell_file", freshPath) {
						t.Error("partial-root failure discarded the finding from a readable account")
					}
					for _, row := range rows {
						if !hasFindingPath(got, row.Check, row.FilePath) {
							t.Errorf("attempt %d: read failure retired %s at %s", attempt, row.Check, row.FilePath)
						}
					}
					for name, want := range before {
						got, err := os.ReadFile(filepath.Join(cfg.StatePath, name))
						if err != nil || string(got) != want {
							t.Errorf("attempt %d: incomplete walk changed %s: %q, error %v", attempt, name, got, err)
						}
					}
				}

				failedPath = ""
				ctx, gaps := WithCoverageGaps(context.Background())
				findings, purge := runParallelWithContext(ctx, cfg, st,
					[]namedCheck{{name: "file_index", fn: CheckFileIndex}}, "deep", true)
				StoreLatestScanFindingsWithGaps(st, purge, findings, gaps.Paths())
				got := st.LatestFindings()
				if freshPath == "" {
					if len(got) != 0 {
						t.Fatalf("recovered scan left findings: %+v", got)
					}
				} else if len(got) != 1 || !hasFindingPath(got, "new_webshell_file", freshPath) {
					t.Fatalf("recovered scan should leave only the new file finding: %+v", got)
				}
			})
		}
	}
}

func TestFileIndexCanceledWarmWalkForcesFullRetry(t *testing.T) {
	homes := t.TempDir()
	languages := filepath.Join(homes, "alice", "public_html", "wp-content", "languages")
	if err := os.MkdirAll(languages, 0755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(languages)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	cacheJSON, err := json.Marshal(dirMtimeCache{languages: info.ModTime().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "dircache.json"), cacheJSON, 0600); err != nil {
		t.Fatal(err)
	}
	withAccountHomeRoots(t, homes)
	previousCount := atomic.LoadInt32(&fileIndexScanCount)
	atomic.StoreInt32(&fileIndexScanCount, 5)
	t.Cleanup(func() { atomic.StoreInt32(&fileIndexScanCount, previousCount) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	interrupt := true
	languagesReads := 0
	withMockOS(t, &mockOS{
		readDir: func(path string) ([]os.DirEntry, error) {
			if path == homes && interrupt {
				cancel()
				return nil, nil
			}
			if path == languages {
				languagesReads++
			}
			if path != homes && !strings.HasPrefix(path, homes+string(filepath.Separator)) {
				return nil, os.ErrNotExist
			}
			return os.ReadDir(path)
		},
		stat: os.Stat, readFile: os.ReadFile, open: os.Open,
	})
	cfg := &config.Config{StatePath: stateDir}
	CheckFileIndex(ctx, cfg, nil)
	if ctx.Err() != context.Canceled || languagesReads != 0 {
		t.Fatal("first scan did not stop before reading the cached directory")
	}
	interrupt = false
	CheckFileIndex(context.Background(), cfg, nil)
	if languagesReads != 1 {
		t.Fatalf("retry read cached directory %d times, want 1", languagesReads)
	}
}
