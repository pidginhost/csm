package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func fileIndexLifecycleFixture(t *testing.T) (*config.Config, *state.Store, string) {
	t.Helper()
	oldCount := atomic.SwapInt32(&fileIndexScanCount, 0)
	t.Cleanup(func() { atomic.StoreInt32(&fileIndexScanCount, oldCount) })
	setFileIndexShrinkSkips(t, 0)
	base := t.TempDir()
	homes := filepath.Join(base, "homes")
	uploads := filepath.Join(homes, "alice", "public_html", "wp-content", "uploads")
	if err := os.MkdirAll(uploads, 0755); err != nil {
		t.Fatal(err)
	}
	withAccountHomeRoots(t, homes)
	withMockOS(t, &mockOS{
		readDir: func(path string) ([]os.DirEntry, error) {
			if path == "/tmp" || path == "/var/tmp" || path == "/dev/shm" {
				return nil, os.ErrNotExist
			}
			return os.ReadDir(path)
		},
		stat: func(path string) (os.FileInfo, error) {
			if path == "/tmp" || path == "/var/tmp" || path == "/dev/shm" {
				return nil, os.ErrNotExist
			}
			return os.Stat(path)
		},
		lstat: os.Lstat, open: os.Open, readFile: os.ReadFile,
	})
	cfg := &config.Config{StatePath: filepath.Join(base, "state")}
	st, err := state.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return cfg, st, uploads
}

func runFileIndexLifecycleScan(cfg *config.Config, st *state.Store) {
	ctx, gaps := WithCoverageGaps(context.Background())
	findings, purge := runParallelWithContext(ctx, cfg, st, []namedCheck{
		{name: "file_index", fn: CheckFileIndex},
		// Completing the other owner exercises shared-name purging too.
		{name: "php_content", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding { return nil }},
	}, "deep", true)
	StoreLatestScanFindingsWithCoverage(st, purge, findings, gaps.Snapshot())
}

func TestReducedFileIndexFindingsSurviveBaselineAndRetireAfterRemoval(t *testing.T) {
	cfg, st, uploads := fileIndexLifecycleFixture(t)
	runFileIndexLifecycleScan(cfg, st)
	paths := map[string]string{
		"c99.php":     "<?php echo 'ready';",
		"plain.php":   "<?php echo 'ready';",
		"payload.php": "<?php eval($_POST['code']);",
	}
	for name, body := range paths {
		if err := os.WriteFile(filepath.Join(uploads, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Directory caching uses seconds, so explicitly advance the directory mtime.
	stamp := time.Now().Add(time.Minute)
	if err := os.Chtimes(uploads, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	runFileIndexLifecycleScan(cfg, st)
	first := st.LatestFindings()
	if len(first) != len(paths) {
		t.Fatalf("first detection = %+v, want one finding per file", first)
	}
	for cycle := 0; cycle < 6; cycle++ {
		runFileIndexLifecycleScan(cfg, st)
		got := st.LatestFindings()
		for _, finding := range first {
			if !hasFindingPath(got, finding.Check, finding.FilePath) {
				t.Errorf("cycle %d retired live finding %+v; latest=%+v", cycle, finding, got)
			}
		}
	}
	for name := range paths {
		if err := os.Remove(filepath.Join(uploads, name)); err != nil {
			t.Fatal(err)
		}
	}
	stamp = stamp.Add(time.Minute)
	if err := os.Chtimes(uploads, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	runFileIndexLifecycleScan(cfg, st)
	if got := st.LatestFindings(); len(got) != 0 {
		t.Fatalf("deleted files still active: %+v", got)
	}
}

func TestReducedFileIndexCachedShrinkPromotesAfterConsecutiveWalks(t *testing.T) {
	cfg, st, uploads := fileIndexLifecycleFixture(t)
	for i := 0; i < 12; i++ {
		if err := os.WriteFile(filepath.Join(uploads, fmt.Sprintf("f%02d.php", i)), []byte("<?php"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	runFileIndexLifecycleScan(cfg, st)
	for i := 2; i < 12; i++ {
		if err := os.Remove(filepath.Join(uploads, fmt.Sprintf("f%02d.php", i))); err != nil {
			t.Fatal(err)
		}
	}
	stamp := time.Now().Add(time.Minute)
	if err := os.Chtimes(uploads, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	for cycle := 1; cycle <= fileIndexShrinkPromoteThreshold; cycle++ {
		runFileIndexLifecycleScan(cfg, st)
		if n := countIndexLines(t, filepath.Join(cfg.StatePath, "fileindex.current")); n != 2 {
			t.Errorf("shrink cycle %d resurrected removed paths: %d entries", cycle, n)
		}
		want := 12
		if cycle == fileIndexShrinkPromoteThreshold {
			want = 2
		}
		if n := countIndexLines(t, filepath.Join(cfg.StatePath, "fileindex.previous")); n != want {
			t.Errorf("shrink cycle %d: baseline has %d entries, want %d", cycle, n, want)
		}
	}
}

func TestReducedFileIndexForcesSixthWalkDespiteUnchangedMtime(t *testing.T) {
	cfg, st, uploads := fileIndexLifecycleFixture(t)
	runFileIndexLifecycleScan(cfg, st)
	info, err := os.Stat(uploads)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(uploads, "c99.php")
	if err := os.WriteFile(path, []byte("<?php echo 'ready';"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(uploads, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	for cycle := 2; cycle <= 6; cycle++ {
		runFileIndexLifecycleScan(cfg, st)
		found := hasFindingPath(st.LatestFindings(), "new_webshell_file", path)
		if found != (cycle == 6) {
			t.Fatalf("cycle %d: found=%v, want the forced sixth walk to detect the file", cycle, found)
		}
	}
}

func TestReducedFileIndexSharedFindingsRequireBothOwnersToComplete(t *testing.T) {
	for _, incomplete := range []string{"file_index", "php_content"} {
		t.Run(incomplete, func(t *testing.T) {
			_, st, _ := fileIndexLifecycleFixture(t)
			rows := []alert.Finding{
				{Check: "obfuscated_php", FilePath: "/home/alice/public_html/a.php", Severity: alert.Critical},
				{Check: "suspicious_php_content", FilePath: "/home/alice/public_html/b.php", Severity: alert.High},
			}
			st.SetLatestFindings(rows)
			checks := []namedCheck{}
			for _, owner := range []string{"file_index", "php_content"} {
				checks = append(checks, namedCheck{name: owner, fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
					if owner == incomplete {
						markCheckIncomplete(ctx, owner)
					}
					return nil
				}})
			}
			ctx, gaps := WithCoverageGaps(context.Background())
			findings, purge := runParallelWithContext(ctx, &config.Config{}, st, checks, "deep", true)
			for _, row := range rows {
				if slices.Contains(purge, row.Check) {
					t.Errorf("incomplete %s authorized purge of %s", incomplete, row.Check)
				}
			}
			StoreLatestScanFindingsWithCoverage(st, purge, findings, gaps.Snapshot())
			if got := st.LatestFindings(); len(got) != len(rows) {
				t.Fatalf("incomplete %s lost shared findings: %+v", incomplete, got)
			}
		})
	}
}

func TestReducedFileIndexRetainsUnreadableActiveContent(t *testing.T) {
	for _, dir := range []string{"uploads", "languages"} {
		t.Run(dir, func(t *testing.T) {
			cfg, st, uploads := fileIndexLifecycleFixture(t)
			path := filepath.Join(filepath.Dir(uploads), dir, "payload.php")
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("<?php eval($_POST['code']);"), 0600); err != nil {
				t.Fatal(err)
			}
			runFileIndexLifecycleScan(cfg, st)
			row := alert.Finding{Check: "obfuscated_php", Severity: alert.Critical, FilePath: path}
			st.SetLatestFindings([]alert.Finding{row})
			fs := osFS.(*mockOS)
			open := fs.open
			fs.open = func(name string) (*os.File, error) {
				if name == path {
					return nil, os.ErrPermission
				}
				return open(name)
			}
			runFileIndexLifecycleScan(cfg, st)
			if got := st.LatestFindings(); !hasFindingPath(got, row.Check, path) {
				t.Fatalf("unreadable content retired prior verdict: %+v", got)
			}
			fs.open = open
			if err := os.WriteFile(path, []byte("<?php // Silence is golden.\n"), 0600); err != nil {
				t.Fatal(err)
			}
			runFileIndexLifecycleScan(cfg, st)
			if got := st.LatestFindings(); len(got) != 0 {
				t.Fatalf("verified benign file retained findings: %+v", got)
			}
		})
	}
}
